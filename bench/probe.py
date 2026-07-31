#!/usr/bin/env python3
"""bench/probe.py — ÉCHANTILLONNEUR D'INGEST. Il ne dit pas pourquoi le débit tombe : il mesure les
grandeurs qui permettent de le TRANCHER.

LA QUESTION À LAQUELLE IL RÉPOND
  Le débit d'ingest s'effondre quand la base grossit. Deux causes se superposaient dans la passe
  précédente, qui ne les séparait pas : le VOLUME déjà en base (maintenance des index/FTS) et la
  CONTENTION de la machine (d'autres travaux). Un débit seul ne peut pas les départager. Trois
  grandeurs le peuvent, et c'est tout ce que ce fichier ajoute :

  CPU DU DAEMON      `utime+stime` du processus. Divisé par les événements ingérés sur l'intervalle,
                     il donne le COÛT CPU PAR ÉVÉNEMENT. S'il monte avec le volume, le travail par
                     ligne grandit VRAIMENT (b-trees plus profonds, index à maintenir) : c'est le
                     VOLUME. S'il reste plat pendant que le débit tombe, le daemon ATTEND.
  CPU DE LA MACHINE  jiffies non-idle de /proc/stat, moins ceux du daemon et du générateur. C'est la
                     charge des AUTRES : c'est la CONTENTION, mesurée, pas déduite du `loadavg`
                     (qui compte aussi les tâches en attente d'E/S et ne dit pas à qui elles sont).
  STALL MÉMOIRE/E-S  PSI du cgroup (`memory.pressure`) et octets lus/écrits au bloc. Un daemon qui
                     n'est ni CPU ni contendu et qui attend quand même attend le STOCKAGE ou la
                     RÉCUPÉRATION MÉMOIRE — et le budget de 2 Gio est appliqué par ce même cgroup,
                     dont le cache de pages est facturé : le plafond peut donc lui-même freiner
                     l'ingest. C'est mesurable ici, en changeant le seul plafond.

CE QU'IL N'INVENTE PAS
  Toutes les colonnes sont des compteurs CUMULATIFS lus tels quels dans /proc et /sys. Aucune n'est
  dérivée : les taux se calculent au rendu, par différence entre deux lignes, pour qu'une ligne
  brute reste vérifiable. Une grandeur indisponible sur la machine (contrôleur cgroup absent) sort
  vide, jamais zéro — zéro serait une mesure, vide est une absence.
"""
import argparse
import base64
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request

HZ = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGESIZE")

# Ordre FIGÉ. Les cinq premières colonnes sont celles de l'échantillonneur d'origine : le rendu
# (bench/report.py) et les CSV déjà publiés continuent de se lire sans changement.
COLUMNS = [
    "t_unix", "events", "db_bytes", "rss_bytes", "loadavg1",
    "wal_bytes", "spool_files",
    "daemon_cpu_s", "gen_cpu_s", "cpu_busy_jiffies", "cpu_total_jiffies",
    "read_bytes", "write_bytes", "syscr", "syscw",
    "cg_mem_current", "cg_mem_file", "cg_pgmajfault", "cg_pgscan", "cg_pgsteal",
    "cg_mem_stall_us", "mem_available_bytes", "swap_used_bytes", "count_ms",
]


def read_first_int(path, prefix, factor=1):
    try:
        with open(path) as fh:
            for line in fh:
                if line.startswith(prefix):
                    return int(line.split()[1]) * factor
    except OSError:
        pass
    return None


def proc_stat_cpu(pid):
    """utime+stime du processus, en secondes. Champs 14/15 de /proc/<pid>/stat — comptés APRÈS le
    `comm` entre parenthèses, qui peut contenir des espaces (d'où le rsplit sur `)`)."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            tail = fh.read().rsplit(")", 1)[1].split()
        return (int(tail[11]) + int(tail[12])) / HZ
    except (OSError, IndexError, ValueError):
        return None


def proc_rss(pid):
    try:
        with open(f"/proc/{pid}/statm") as fh:
            return int(fh.read().split()[1]) * PAGE
    except (OSError, IndexError, ValueError):
        return None


def proc_io(pid):
    out = {}
    try:
        with open(f"/proc/{pid}/io") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                if k in ("read_bytes", "write_bytes", "syscr", "syscw"):
                    out[k] = int(v)
    except OSError:
        pass
    return out


def machine_cpu():
    """(busy, total) en jiffies depuis le démarrage. busy = total - idle - iowait : le temps où un
    cœur exécutait vraiment quelque chose."""
    try:
        with open("/proc/stat") as fh:
            f = [int(x) for x in fh.readline().split()[1:]]
    except (OSError, ValueError):
        return None, None
    total = sum(f)
    idle = f[3] + (f[4] if len(f) > 4 else 0)
    return total - idle, total


def cgroup_dir(pid):
    """Répertoire cgroup v2 du processus. Sans lui, les colonnes cgroup sortent vides — le budget de
    2 Gio étant APPLIQUÉ par ce cgroup, c'est là que se lisent le cache de pages facturé et le stall."""
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            for line in fh:
                if line.startswith("0::"):
                    rel = line.strip().split("::", 1)[1].lstrip("/")
                    d = os.path.join("/sys/fs/cgroup", rel)
                    return d if os.path.isdir(d) else None
    except OSError:
        pass
    return None


def cgroup_sample(d):
    out = {}
    if not d:
        return out
    try:
        with open(os.path.join(d, "memory.current")) as fh:
            out["cg_mem_current"] = int(fh.read().strip())
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(d, "memory.stat")) as fh:
            st = dict(line.split()[:2] for line in fh if len(line.split()) >= 2)
        for key, col in (("file", "cg_mem_file"), ("pgmajfault", "cg_pgmajfault"),
                         ("pgscan", "cg_pgscan"), ("pgsteal", "cg_pgsteal")):
            if key in st:
                out[col] = int(st[key])
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(d, "memory.pressure")) as fh:
            for line in fh:
                if line.startswith("some"):
                    for tok in line.split():
                        if tok.startswith("total="):
                            out["cg_mem_stall_us"] = int(tok.split("=")[1])
    except (OSError, ValueError):
        pass
    return out


def meminfo():
    out = {}
    try:
        with open("/proc/meminfo") as fh:
            m = {}
            for line in fh:
                k, _, v = line.partition(":")
                if k in ("MemAvailable", "SwapTotal", "SwapFree"):
                    m[k] = int(v.split()[0]) * 1024
        out["mem_available_bytes"] = m.get("MemAvailable")
        if "SwapTotal" in m and "SwapFree" in m:
            out["swap_used_bytes"] = m["SwapTotal"] - m["SwapFree"]
    except OSError:
        pass
    return out


def count_events(base, host, user, password, timeout=180):
    """Compte les lignes PAR LE VRAI CHEMIN (/api/query). Son propre coût est MESURÉ et publié
    (colonne `count_ms`) : à gros volume un comptage est un scan, et un échantillonneur qui
    consomme la machine qu'il observe doit dire combien il consomme."""
    body = json.dumps({"soql": "search | stats count", "from": 0, "to": 0,
                       "interactive": True}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/api/query", data=body, method="POST")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    req.add_header("Host", host)
    req.add_header("Content-Type", "application/json")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            n = json.loads(r.read())["rows"][0][0]
    except (urllib.error.URLError, OSError, KeyError, IndexError, ValueError, json.JSONDecodeError):
        n = None
    return n, round((time.monotonic() - t0) * 1000, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True, help="PID du daemon")
    ap.add_argument("--gen-pid", type=int, default=0, help="PID du générateur (sa part de CPU est "
                    "retirée de la charge machine pour isoler la CONTENTION des tiers)")
    ap.add_argument("--db", required=True)
    ap.add_argument("--spool", default="")
    ap.add_argument("--base", default="http://127.0.0.1:7411")
    ap.add_argument("--host-header", default="localhost")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--interval", type=float, default=60.0)
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()

    new = not os.path.exists(a.out) or os.path.getsize(a.out) == 0
    cg = cgroup_dir(a.pid)
    with open(a.out, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        if new:
            w.writeheader()
            fh.flush()
        while os.path.exists(f"/proc/{a.pid}"):
            n, ms = count_events(a.base, a.host_header, a.user, a.password)
            busy, total = machine_cpu()
            row = {"t_unix": int(time.time()), "events": n, "count_ms": ms,
                   "rss_bytes": proc_rss(a.pid), "daemon_cpu_s": proc_stat_cpu(a.pid),
                   "cpu_busy_jiffies": busy, "cpu_total_jiffies": total}
            if a.gen_pid:
                row["gen_cpu_s"] = proc_stat_cpu(a.gen_pid)
            try:
                row["loadavg1"] = open("/proc/loadavg").read().split()[0]
            except OSError:
                pass
            for path, col in ((a.db, "db_bytes"), (a.db + "-wal", "wal_bytes")):
                try:
                    row[col] = os.path.getsize(path)
                except OSError:
                    pass
            if a.spool:
                try:
                    row["spool_files"] = sum(1 for x in os.listdir(a.spool) if x.startswith("ingest-"))
                except OSError:
                    pass
            row.update(proc_io(a.pid))
            row.update(cgroup_sample(cg))
            row.update(meminfo())
            if row.get("events") is not None:
                w.writerow(row)
                fh.flush()
            time.sleep(a.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
