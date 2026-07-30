#!/usr/bin/env python3
"""bench/measure.py — HARNAIS DE MESURE. Il ne prétend rien : il mesure, il horodate, il qualifie.

CE QU'IL MESURE PAR CELLULE
  latence      p50 et p95 (rang le plus proche) sur N répétitions, plus le premier tir isolé
               (cache froid côté SQLite) ; côté client (mur) ET côté serveur (`stats.elapsed_ms`,
               `stats.server_ms`, `stats.sem_wait_ms` renvoyés par le daemon).
  RSS CRÊTE    échantillonnage de /proc/<pid>/statm toutes les 15 ms PENDANT la requête. C'est une
               MESURE, jamais une estimation. `VmHWM` (crête que le noyau tient lui-même depuis le
               démarrage du processus) est relevé en plus, avant/après.
  LECTURE      /proc/<pid>/io `read_bytes` — octets réellement lus au bloc. 0 = servi depuis le
               cache de pages, ce qui est un RÉSULTAT à publier, pas une erreur.
  PRESSION     loadavg et swap avant/après. Un chiffre pris pendant que la machine swappe est FAUX :
               la cellule est marquée `swap_suspect` et doit être rejouée.

CE QU'IL NE MESURE PAS
  Rien n'est déduit d'un autre chiffre. Une cellule qui échoue (budget dépassé, 4xx, 5xx) est
  écrite avec son erreur — pas retirée du tableau.
"""
import argparse
import base64
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ------------------------------------------------------------------ /proc
def proc_rss_bytes(pid):
    try:
        with open(f"/proc/{pid}/statm") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGESIZE")
    except (OSError, IndexError, ValueError):
        return 0


def proc_vmhwm_bytes(pid):
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def proc_io_read_bytes(pid):
    try:
        with open(f"/proc/{pid}/io") as fh:
            for line in fh:
                if line.startswith("read_bytes:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def host_pressure():
    la = open("/proc/loadavg").read().split()[:3]
    mem = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            k, _, v = line.partition(":")
            if k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                mem[k] = int(v.split()[0]) * 1024
    return {"loadavg": [float(x) for x in la],
            "mem_available_bytes": mem.get("MemAvailable", 0),
            "swap_used_bytes": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)}


class RssSampler(threading.Thread):
    """Échantillonne le RSS pendant la requête. 15 ms : assez fin pour attraper la crête d'un scan
    de quelques secondes, assez grossier pour ne pas peser sur la mesure."""

    def __init__(self, pid, interval=0.015):
        super().__init__(daemon=True)
        self.pid, self.interval = pid, interval
        self.peak, self.samples, self._stop = 0, 0, threading.Event()

    def run(self):
        while not self._stop.is_set():
            r = proc_rss_bytes(self.pid)
            if r > self.peak:
                self.peak = r
            self.samples += 1
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        self.join(timeout=2)
        return self.peak, self.samples


# ------------------------------------------------------------------ client HTTP
class Client:
    def __init__(self, base, user, password, host_header):
        self.base, self.host = base.rstrip("/"), host_header
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def call(self, path, body=None, method=None, timeout=300):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"))
        req.add_header("Authorization", self.auth)
        req.add_header("Host", self.host)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                try:
                    return r.status, json.loads(raw)
                except json.JSONDecodeError:
                    return r.status, {"_raw": raw[:400].decode("utf-8", "replace")}
        except urllib.error.HTTPError as e:
            return e.code, {"_error": e.read()[:400].decode("utf-8", "replace")}
        except OSError as e:
            return 0, {"_error": f"{type(e).__name__}: {e}"}


# ------------------------------------------------------------------ matrice
def query_classes(end_ts):
    """5 classes. Chaque entrée : (id, libellé, requête). `kind` dit par quelle porte on entre :
    `gxql` = POST /api/query champ `soql` (le compilateur GXQL) ; `search` = GET /api/search
    (la barre plein-texte, seul chemin CÂBLÉ SUR FTS5 — c'est le point de comparaison décisif)."""
    return [
        # (0) LE PLANCHER. Requête dont le SQL ne coûte rien (seek d'index sur une source qui
        #     n'existe pas, 0 ligne). Ce que cette cellule mesure n'est donc PAS du travail de
        #     base : c'est le coût FIXE d'une requête. Sans elle on attribuerait ce coût aux
        #     classes suivantes et on conclurait à tort que « tout coûte 50 ms ».
        dict(id="C0-plancher", kind="gxql",
             label="PLANCHER : seek sur une source inexistante (0 ligne)",
             soql="search source=source-qui-nexiste-pas | stats count"),
        # (i) scan filtré + agrégat simple
        dict(id="C1-scan-agg", kind="gxql",
             label="scan filtré + agrégat (source + severity)",
             soql="search source=auditd severity>=2 | stats count"),
        dict(id="C1b-scan-agg-dc", kind="gxql",
             label="scan filtré + dc() sur colonne réelle",
             soql="search source=k8s-log | stats dc(host)"),
        # (ii) plein-texte / regex sur le message
        dict(id="C2-free-term", kind="gxql",
             label="terme libre sur message (compile en LIKE '%…%')",
             soql="search anomalieplumebench | stats count"),
        dict(id="C2b-regex-msg", kind="gxql",
             label="regex sur message (REGEXP, UDF Rust)",
             soql="search message=~anomalieplumebench | stats count"),
        dict(id="C2c-fts-bar", kind="search",
             label="MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)",
             q="anomalieplumebench"),
        # Comparaison HONNÊTE avec la ligne du dessus : /api/search rend des LIGNES (100 max), pas
        # un compte. Comparer sa latence à celle d'un `stats count` serait comparer deux travaux
        # différents. Cette cellule fait, en GXQL, exactement ce que fait /api/search.
        dict(id="C2d-free-term-rows", kind="gxql",
             label="MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)",
             soql="search anomalieplumebench | table ts,host,source,message", limit=100, offset=0),
        dict(id="C2e-free-term-common", kind="gxql",
             label="terme libre PEU sélectif (1 ligne sur 10) en LIKE",
             soql="search sessionplumebench | stats count"),
        # (iii) group-by multi-dimensions à haute cardinalité
        dict(id="C3-groupby-hi", kind="gxql",
             label="group-by 3 dims haute cardinalité (src_ip,host,source)",
             soql="search | stats count by src_ip,host,source | sort -count | head 50"),
        dict(id="C3b-groupby-routable", kind="gxql",
             label="group-by 2 dims ROUTABLE en rollup (source,severity)",
             soql="search | stats count by source,severity"),
        dict(id="C3c-groupby-json", kind="gxql",
             label="group-by sur champ ÉTENDU indexé (action) + colonne",
             soql="search | stats count by action,source | sort -count | head 50"),
        # (iv) récupération RAW paginée
        dict(id="C4-raw-page1", kind="gxql",
             label="RAW paginé page 1 (limit 200, offset 0)",
             soql="search severity>=1 | table ts,host,source,severity,message",
             limit=200, offset=0),
        dict(id="C4b-raw-deep", kind="gxql",
             label="RAW paginé page profonde (offset 200 000)",
             soql="search severity>=1 | table ts,host,source,severity,message",
             limit=200, offset=200000),
        dict(id="C4c-raw-keyset", kind="gxql",
             label="RAW paginé en keyset (curseur, sans offset)",
             soql="search severity>=1", limit=200, keyset=True),
        # Le client DEMANDE le curseur sur un pipeline PROJETÉ — c'est ce que fait toute récupération
        # RAW réelle (on projette des colonnes). À comparer à C4c (même demande, sans projection) : si
        # les deux ne se ressemblent pas, c'est que la projection fait perdre le curseur.
        dict(id="C4d-keyset-projete", kind="gxql",
             label="keyset DEMANDÉ sur un pipeline PROJETÉ (| table)",
             soql="search severity>=1 | table ts,host,source,severity,message",
             limit=200, keyset=True),
        # (v) regex sur un champ ÉTENDU (JSON) — le cas le plus coûteux, et celui demandé
        dict(id="C5-regex-json-planted", kind="gxql",
             label="regex sur champ ÉTENDU planté (fields.needle)",
             soql="search needle=~objetplumebench | stats count"),
        dict(id="C5b-regex-json-cold", kind="gxql",
             label="regex sur champ ÉTENDU NON indexé (fields.object)",
             soql="search object=~[0-9a-f]{6}c | stats count"),
        dict(id="C5c-eq-json-hot", kind="gxql",
             label="égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)",
             soql="search user=bench-user-0007 | stats count"),
    ]


def windows(end_ts):
    return [
        dict(id="1h", label="dernière heure", frm=end_ts - 3600, to=end_ts),
        dict(id="24h", label="dernier jour", frm=end_ts - 86400, to=end_ts),
        dict(id="all", label="tout", frm=0, to=0),
    ]


# ------------------------------------------------------------------ exécution d'une cellule
def run_one(cli, pid, spec, win, interactive):
    io0 = proc_io_read_bytes(pid)
    smp = RssSampler(pid)
    smp.start()
    t0 = time.monotonic()
    if spec["kind"] == "search":
        qs = f"/api/search?q={urllib.parse.quote(spec['q'])}"
        if win["frm"]:
            qs += f"&from={win['frm']}&to={win['to']}"
        status, body = cli.call(qs)
    else:
        payload = {"soql": spec["soql"], "from": win["frm"], "to": win["to"],
                   "interactive": interactive}
        for k in ("limit", "offset"):
            if k in spec:
                payload[k] = spec[k]
        if spec.get("keyset"):
            payload["keyset"] = True
        status, body = cli.call("/api/query", payload)
    wall_ms = (time.monotonic() - t0) * 1000.0
    peak, nsamp = smp.stop()
    io1 = proc_io_read_bytes(pid)
    st = (body or {}).get("stats") or {}
    return dict(
        status=status, wall_ms=round(wall_ms, 2),
        elapsed_ms=st.get("elapsed_ms"), server_ms=st.get("server_ms"),
        sem_wait_ms=st.get("sem_wait_ms"),
        rows=st.get("rows", len((body or {}).get("results", []) or [])),
        truncated=st.get("truncated"), served_from=st.get("served_from"),
        approx=st.get("approx"), total=(body or {}).get("total"),
        peak_rss_bytes=peak, rss_samples=nsamp, read_bytes=io1 - io0,
        error=(body or {}).get("_error") or (body or {}).get("error"),
        compiled_sql=(body or {}).get("compiled_sql"),
    )


def pctl(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * len(s) + 0.5)) - 1))
    return s[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:7000")
    ap.add_argument("--host-header", default="localhost")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--pid", type=int, required=True, help="PID du daemon — la RSS est LUE sur lui")
    ap.add_argument("--end-ts", type=int, required=True, help="fin de la fenêtre de données")
    ap.add_argument("--config-id", required=True, help="étiquette de la configuration mesurée")
    ap.add_argument("--config-meta", default="{}", help="JSON : fts_fields, mask, cold, version…")
    ap.add_argument("--reps", type=int, default=7)
    ap.add_argument("--reps-slow", type=int, default=3,
                    help="répétitions quand le 1er tir dépasse --slow-ms")
    ap.add_argument("--slow-ms", type=float, default=3000.0)
    ap.add_argument("--interactive", type=int, default=1,
                    help="1 = budget interactif 60 s ; 0 = budget auto 5 s")
    ap.add_argument("--only", default="", help="liste de sous-chaînes d'id de classe séparées par "
                    "des virgules ; vide = toutes les classes")
    ap.add_argument("--windows", default="1h,24h,all")
    ap.add_argument("-o", "--out", required=True, help="JSONL — une ligne par cellule")
    a = ap.parse_args()

    cli = Client(a.base, a.user, a.password, a.host_header)
    meta = json.loads(a.config_meta)
    wanted = [w for w in windows(a.end_ts) if w["id"] in a.windows.split(",")]
    pats = [p for p in a.only.split(",") if p]
    classes = [c for c in query_classes(a.end_ts)
               if not pats or any(p in c["id"] for p in pats)]
    if not classes:
        sys.exit(f"--only={a.only!r} ne retient aucune classe")

    with open(a.out, "a", encoding="utf-8") as out:
        for spec in classes:
            for win in wanted:
                p_before = host_pressure()
                hwm_before = proc_vmhwm_bytes(a.pid)
                first = run_one(cli, a.pid, spec, win, bool(a.interactive))
                reps = a.reps if (first["wall_ms"] or 0) < a.slow_ms else a.reps_slow
                runs = [first]
                for _ in range(max(reps - 1, 0)):
                    runs.append(run_one(cli, a.pid, spec, win, bool(a.interactive)))
                p_after = host_pressure()
                hwm_after = proc_vmhwm_bytes(a.pid)
                ok = [r for r in runs if r["status"] == 200 and not r["error"]]
                walls = [r["wall_ms"] for r in ok]
                servs = [r["server_ms"] for r in ok if r["server_ms"] is not None]
                elaps = [r["elapsed_ms"] for r in ok if r["elapsed_ms"] is not None]
                swap_delta = p_after["swap_used_bytes"] - p_before["swap_used_bytes"]
                row = dict(
                    config_id=a.config_id, config=meta,
                    class_id=spec["id"], label=spec["label"], kind=spec["kind"],
                    query=spec.get("soql") or spec.get("q"),
                    limit=spec.get("limit"), offset=spec.get("offset"),
                    keyset=bool(spec.get("keyset")),
                    window=win["id"], window_from=win["frm"], window_to=win["to"],
                    reps=len(runs), reps_ok=len(ok),
                    cold_first_wall_ms=first["wall_ms"],
                    wall_p50_ms=pctl(walls, 50), wall_p95_ms=pctl(walls, 95),
                    server_p50_ms=pctl(servs, 50), server_p95_ms=pctl(servs, 95),
                    sql_p50_ms=pctl(elaps, 50), sql_p95_ms=pctl(elaps, 95),
                    sem_wait_max_ms=max((r["sem_wait_ms"] or 0 for r in ok), default=None),
                    rows=(ok[0]["rows"] if ok else None),
                    total=(ok[0]["total"] if ok else None),
                    truncated=any(bool(r["truncated"]) for r in ok),
                    served_from=(ok[0]["served_from"] if ok else None),
                    approx=(ok[0]["approx"] if ok else None),
                    peak_rss_bytes=max((r["peak_rss_bytes"] for r in runs), default=0),
                    vmhwm_before_bytes=hwm_before, vmhwm_after_bytes=hwm_after,
                    read_bytes_first=first["read_bytes"],
                    read_bytes_total=sum(r["read_bytes"] for r in runs),
                    rss_samples_first=first["rss_samples"],
                    statuses=sorted({r["status"] for r in runs}),
                    errors=sorted({r["error"] for r in runs if r["error"]}),
                    compiled_sql=first.get("compiled_sql"),
                    pressure_before=p_before, pressure_after=p_after,
                    swap_delta_bytes=swap_delta,
                    # Un chiffre pris pendant que la machine swappe est FAUX. On ne le corrige pas,
                    # on le MARQUE : la cellule doit être rejouée.
                    swap_suspect=bool(swap_delta > 8 * 1024 * 1024),
                    measured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                )
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                out.flush()
                # Le daemon tourne sous un plafond mémoire DUR (MemoryMax, sans swap). S'il vient
                # d'être tué, tout ce qui suivrait serait un échec de connexion enregistré comme une
                # mesure. On l'écrit comme ce que c'est — un dépassement du budget — et on s'arrête.
                if not os.path.exists(f"/proc/{a.pid}"):
                    out.write(json.dumps(dict(
                        config_id=a.config_id, config=meta, class_id=spec["id"],
                        label=spec["label"], kind=spec["kind"], window=win["id"],
                        daemon_died_after_this_cell=True,
                        note=("le daemon n'existe plus après cette cellule : sous MemoryMax sans "
                              "swap, cela signifie un DÉPASSEMENT DU BUDGET (kill du noyau). "
                              "Les cellules suivantes ne sont PAS mesurées."),
                        measured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    ), ensure_ascii=False) + "\n")
                    out.flush()
                    print(f"\n!!! le daemon (pid {a.pid}) a disparu après {spec['id']}/{win['id']} "
                          f"— DÉPASSEMENT DU BUDGET DE MÉMOIRE. Arrêt.", flush=True)
                    sys.exit(3)
                mib = lambda b: (b or 0) / 2**20
                print(f"{a.config_id:22} {spec['id']:24} {win['id']:4} "
                      f"p50={row['wall_p50_ms'] or -1:9.1f}ms p95={row['wall_p95_ms'] or -1:9.1f}ms "
                      f"rss_max={mib(row['peak_rss_bytes']):7.1f}Mio "
                      f"lu={mib(row['read_bytes_first']):8.1f}Mio "
                      f"n={row['rows']} {'/'.join(map(str, row['statuses']))}"
                      f"{' SWAP!' if row['swap_suspect'] else ''}"
                      f"{' ' + (row['served_from'] or '') if row['served_from'] else ''}",
                      flush=True)


if __name__ == "__main__":
    main()
