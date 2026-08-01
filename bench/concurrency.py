#!/usr/bin/env python3
"""bench/concurrency.py — PLUSIEURS ANALYSTES EN MÊME TEMPS, et d'abord : LA MÊME RÉPONSE ?

POURQUOI CE FICHIER EXISTE
  `measure.py` tire UNE requête à la fois. `sem_wait_ms` y est donc nul par construction, et
  docs/BENCHMARK.md le dit lui-même : « la concurrence n'est pas mesurée ». Or la condition d'usage
  d'une équipe, c'est cinq ou six analystes qui lancent de très grosses requêtes EN MÊME TEMPS. Et
  le sémaphore de l'interactif (`PLUME_QUERY_CONCURRENCY`, défaut 3, `daemon/src/server.rs:254`) a
  été BAISSÉ de 8 à 3 comme LEVIER DE RAM : la concurrence s'échange directement contre le budget de
  2 Gio, et personne n'avait mesuré le taux de change.

CE QU'IL MESURE, DANS CET ORDRE — LA VITESSE N'EST PAS LE PREMIER AXE
  1. LA JUSTESSE. Trois défauts de CORRECTION viennent d'être trouvés dans les chemins d'agrégat, et
     AUCUN n'était visible au banc de latence. Chaque réponse concurrente est donc comparée, PAR SA
     VALEUR (empreinte stable de `parity.py`, insensible à l'ordre), à la réponse obtenue SEUL sur la
     même base et le même binaire. Une réponse fausse sous concurrence serait bien plus grave qu'une
     réponse lente. Le harnais SORT EN ERREUR si un agrégat diverge.
  2. LA RAM SOUS BUDGET APPLIQUÉ. Le daemon tourne dans un cgroup `MemoryMax` sans swap. On relève sa
     RSS (/proc), la mémoire du CGROUP (`memory.current` — c'est ELLE que le noyau compare au
     plafond, page cache comprise) et `memory.events` : `max` = combien de fois le plafond a été
     atteint (donc du travail de reclaim), `oom_kill` = combien de fois le noyau a tué. La question
     n'est pas « ça tient ? » mais « à combien d'analystes ça ne tient plus, et QUOI alors ».
  3. LA LATENCE ET LE POINT DE RUPTURE. Un BALAYAGE de concurrence, pas un point isolé : c'est la
     COURBE qui donne la capacité par nœud. Par analyste (p50/p95) ET en débit agrégé — un système
     peut ralentir chaque requête tout en servant plus de travail au total, et l'inverse est vrai.
  4. `sem_wait_ms`. Sous concurrence il devient non nul, et c'est lui qui sépare « la requête est
     lente » de « la requête attendait son tour ». Sans lui, un p95 sous charge est illisible.

CE QU'IL NE FAIT PAS
  Il ne déduit rien. Une requête qui échoue est écrite avec son statut et son erreur. Un niveau pris
  pendant que la MACHINE swappe est marqué `swap_suspect` : la charge doit peser sur le daemon, pas
  sur l'hôte, et la seule façon honnête de le dire est de mesurer les deux séparément.
"""
import argparse
import json
import os
import re
import sys
import threading
import time

# IMPORTS, PAS COPIES. Le mélange de requêtes, les fenêtres, le client HTTP, le seuil de swap et
# l'empreinte de réponse viennent des harnais DÉJÀ publiés. Deux conséquences voulues :
#   * ce fichier ne peut pas mesurer une AUTRE matrice que celle du document ;
#   * si un de ces noms disparaît, ce harnais s'arrête À L'IMPORT, avant d'avoir produit un seul
#     chiffre — l'équivalent Python d'un échec de LIEN, qui est le meilleur moment pour échouer.
from measure import (SWAP_SUSPECT_BYTES, Client, host_pressure, pctl, proc_io_read_bytes,
                     proc_rss_bytes, proc_vmhwm_bytes, query_classes, windows)
from parity import digest_rows, is_set_derived

# UNE classe est « lourde » à partir de ce multiple du PLANCHER MESURÉ dans la même passe (la requête
# la moins chère observée = le coût FIXE d'une requête, pas du travail de base). Ce n'est pas un goût :
# c'est la frontière entre « ça coûte ce que coûte une requête » et « ça fait du travail ». La famille
# du plancher s'exclut ainsi ELLE-MÊME du mélange lourd — plancher >= 10 x plancher est faux.
HEAVY_FACTOR = 10.0


# ------------------------------------------------------------------ cgroup (le budget APPLIQUÉ)
def cgroup_dir(pid):
    """Le cgroup v2 du daemon. C'est LÀ que `MemoryMax` est appliqué : lire la RSS du processus ne
    suffit pas, parce que le noyau compare au plafond la mémoire du CGROUP (anon + page cache
    facturé). Un daemon dont la RSS reste à 900 Mio peut très bien passer son temps en reclaim
    parce que le cgroup, lui, tape le plafond."""
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            for line in fh:
                p = line.strip().split(":", 2)
                if len(p) == 3 and p[0] == "0":
                    return "/sys/fs/cgroup" + p[2]
    except OSError:
        pass
    return None


def cg_int(cgdir, name):
    try:
        with open(os.path.join(cgdir, name)) as fh:
            return int(fh.read().split()[0])
    except (OSError, ValueError, IndexError, TypeError):
        return None


def cg_events(cgdir):
    """`memory.events` : le journal du plafond. `max` s'incrémente à chaque fois que le cgroup a
    TOUCHÉ `memory.max` et a dû récupérer de la mémoire pour continuer ; `oom_kill` à chaque fois
    qu'il n'a pas pu. La différence entre les deux est exactement la différence entre « dégradé » et
    « tué » — c'est la réponse à « qu'arrive-t-il quand le budget ne tient plus »."""
    out = {}
    try:
        with open(os.path.join(cgdir, "memory.events")) as fh:
            for line in fh:
                k, _, v = line.partition(" ")
                try:
                    out[k] = int(v)
                except ValueError:
                    pass
    except (OSError, TypeError):
        pass
    return out


class LoadSampler(threading.Thread):
    """Échantillonne PENDANT le niveau : RSS du daemon ET mémoire du cgroup. 15 ms — le même pas que
    `measure.py`, pour que les crêtes des deux documents soient comparables."""

    def __init__(self, pid, cgdir, interval=0.015):
        super().__init__(daemon=True)
        self.pid, self.cgdir, self.interval = pid, cgdir, interval
        self.peak_rss, self.peak_cg, self.samples = 0, 0, 0
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            r = proc_rss_bytes(self.pid)
            if r > self.peak_rss:
                self.peak_rss = r
            c = cg_int(self.cgdir, "memory.current") if self.cgdir else None
            if c and c > self.peak_cg:
                self.peak_cg = c
            self.samples += 1
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        self.join(timeout=3)
        return self.peak_rss, self.peak_cg, self.samples


# ------------------------------------------------------------------ une requête = une mesure + une réponse
def one_request(cli, spec, win, interactive=True, timeout=600):
    """UNE requête, relevée sur ses DEUX axes à la fois : le TEMPS (mur, serveur, attente de permit)
    et la RÉPONSE (empreinte + total + drapeaux). Les deux dans le même appel, sinon on comparerait
    la latence d'un tir à la justesse d'un autre."""
    t0 = time.monotonic()
    if spec["kind"] == "search":
        import urllib.parse as _u
        qs = f"/api/search?q={_u.quote(spec['q'])}"
        if win["frm"]:
            qs += f"&from={win['frm']}&to={win['to']}"
        status, body = cli.call(qs, timeout=timeout)
    else:
        payload = {"soql": spec["soql"], "from": win["frm"], "to": win["to"],
                   "interactive": interactive}
        for k in ("limit", "offset"):
            if k in spec:
                payload[k] = spec[k]
        if spec.get("keyset"):
            payload["keyset"] = True
        status, body = cli.call("/api/query", payload, timeout=timeout)
    wall_ms = (time.monotonic() - t0) * 1000.0
    body = body if isinstance(body, dict) else {}
    st = body.get("stats") or {}
    rows = body.get("results") if spec["kind"] == "search" else body.get("rows")
    rows = rows if isinstance(rows, list) else None
    rec = dict(
        status=status, wall_ms=round(wall_ms, 2),
        server_ms=st.get("server_ms"), elapsed_ms=st.get("elapsed_ms"),
        # `sem_wait_ms` n'existe que sur les routes qui le PUBLIENT. `None` n'est pas 0 : c'est
        # « la route ne le dit pas », et le rapport doit pouvoir faire la différence.
        sem_wait_ms=st.get("sem_wait_ms"),
        rows=(len(rows) if rows is not None else None),
        total=body.get("total"), truncated=bool(st.get("truncated")),
        served_from=st.get("served_from"),
        digest=(digest_rows(rows) if rows is not None else None),
        error=body.get("_error") or body.get("error"),
    )
    # Un agrégat tient en quelques lignes : on garde ses VALEURS, c'est le chiffre qu'un lecteur veut
    # pouvoir contredire (« 58 747 contre 289 »). Borné, sinon une page RAW ferait exploser le JSONL.
    if rows is not None and len(rows) <= 8:
        rec["values"] = rows
    return rec


# ------------------------------------------------------------------ phase 0 : LE DAEMON EST-IL AU REPOS ?
def wait_quiescent(cli, spec, win, need=3, timeout_s=420, period_s=5.0):
    """MESURER UN DAEMON QUI VIENT DE DÉMARRER, C'EST MESURER SON DÉMARRAGE.

    Au boot, plume lance un `ANALYZE` complet EN ARRIÈRE-PLAN qui prend le lock writer (~3 min sur
    cette base, `daemon/src/server.rs`), et la boucle de rollups tourne. Or le chemin interactif
    consulte la base (masques, couverture des rollups) AVANT de prendre son permit : tant que ces
    travaux tiennent le verrou, toute requête attend — et c'est du démarrage, pas de la concurrence.

    LA SONDE N'EST PAS LE TEMPS DE LA REQUÊTE, c'est son ATTENTE AVANT MOTEUR (`sem_wait_ms`), qui
    ne dépend PAS de la requête choisie : n'importe quelle classe la révèle. On attend `need` tirs
    consécutifs sous la milliseconde — c'est-à-dire indiscernables de zéro à la résolution publiée.
    Le temps qu'il a fallu est RENDU, parce qu'il est lui-même une mesure : c'est la durée pendant
    laquelle un nœud qui redémarre fait attendre ses analystes."""
    t0 = time.monotonic()
    streak, seen = 0, []
    while time.monotonic() - t0 < timeout_s:
        r = one_request(cli, spec, win)
        w = r.get("sem_wait_ms")
        seen.append(dict(t_s=round(time.monotonic() - t0, 1), sem_wait_ms=w,
                         wall_ms=r["wall_ms"], status=r["status"]))
        if w is not None and w < 1.0:
            streak += 1
            if streak >= need:
                return dict(quiescent=True, seconds=round(time.monotonic() - t0, 1),
                            probes=seen, need=need)
        else:
            streak = 0
        time.sleep(period_s)
    return dict(quiescent=False, seconds=round(time.monotonic() - t0, 1), probes=seen, need=need,
                why=f"toujours pas {need} tirs consécutifs sous la ms après {timeout_s}s")


# ------------------------------------------------------------------ phase 1 : la RÉFÉRENCE SEUL
def probe_solo(cli, classes, win, reps):
    """LA RÉFÉRENCE. Une requête à la fois, aucune charge, MÊME base et MÊME binaire que la suite.
    Sans elle on ne saurait pas de quoi on mesure l'écart. Elle rend trois choses, et les trois
    servent :
      (1) le COÛT SEUL de chaque classe -> c'est de là que le mélange est DÉRIVÉ ;
      (2) la RÉPONSE de référence (empreinte + total) -> c'est à elle que toute réponse concurrente
          est comparée ;
      (3) la STABILITÉ de cette réponse. Une classe dont l'empreinte varie DÉJÀ seule ne peut pas
          servir à accuser la concurrence : elle est retirée du verdict de justesse, et le retrait
          est PUBLIÉ. Accuser la concurrence d'une divergence qu'on observe sans elle serait une
          fausse alerte, et une fausse alerte détruit la valeur des vraies."""
    out = {}
    for spec in classes:
        runs = [one_request(cli, spec, win) for _ in range(reps)]
        ok = [r for r in runs if r["status"] == 200 and not r["error"]]
        digests = {r["digest"] for r in ok}
        totals = {json.dumps(r["total"]) for r in ok}
        stable = len(ok) == len(runs) and len(digests) == 1 and len(totals) == 1
        out[spec["id"]] = dict(
            class_id=spec["id"], label=spec["label"], kind=spec["kind"],
            query=spec.get("soql") or spec.get("q"),
            reps=len(runs), reps_ok=len(ok),
            p50_ms=pctl([r["wall_ms"] for r in ok], 50),
            p95_ms=pctl([r["wall_ms"] for r in ok], 95),
            sem_wait_ms=max((r["sem_wait_ms"] or 0 for r in ok), default=None),
            publishes_sem_wait=any(r["sem_wait_ms"] is not None for r in ok),
            rows=(ok[0]["rows"] if ok else None),
            digest=(ok[0]["digest"] if ok else None),
            total=(ok[0]["total"] if ok else None),
            values=(ok[0].get("values") if ok else None),
            served_from=(ok[0]["served_from"] if ok else None),
            truncated=(ok[0]["truncated"] if ok else None),
            set_derived=is_set_derived(spec),
            stable=stable,
            why_unstable=(None if stable else
                          ("une répétition a échoué" if len(ok) != len(runs) else
                           f"{len(digests)} empreintes / {len(totals)} totaux differents SEUL")),
            errors=sorted({r["error"] for r in runs if r["error"]}),
            statuses=sorted({r["status"] for r in runs}),
        )
        p50 = out[spec['id']]['p50_ms']
        print(f"  solo {spec['id']:24} p50={-1 if p50 is None else p50:9.1f}ms "
              f"n={out[spec['id']]['rows']} {'stable' if stable else 'INSTABLE SEUL'}",
              file=sys.stderr, flush=True)
    return out


def family_of(class_id):
    """La FAMILLE d'une classe, lue dans son identifiant : `C3b-groupby-routable` -> famille 3. Ce
    n'est pas une convention inventée ici — c'est la taxonomie que `measure.py` numérote et que
    docs/BENCHMARK.md publie (scan+agrégat, plein-texte/regex, group-by multi-dim, RAW paginé, champ
    étendu, colonne host). Dériver le mélange des familles plutôt que d'écrire une liste d'ids a une
    conséquence : ajouter une classe à `measure.py` peut changer le mélange, et c'est voulu."""
    m = re.match(r"^C(\d+)", class_id or "")
    return m.group(1) if m else "?"


def derive_mix(probe):
    """LE MÉLANGE N'EST PAS UNE LISTE DE GOÛTS — six analystes ne font pas tous la même chose, et une
    charge homogène cache exactement les interactions qu'on cherche.

    RÈGLE, DÉRIVÉE DE LA MESURE QUI VIENT D'ÊTRE FAITE :
      * le PLANCHER est la requête la moins chère observée dans la passe (le coût fixe d'une requête) ;
      * une famille entre dans le mélange par son représentant LE PLUS COÛTEUX, et seulement s'il
        coûte au moins HEAVY_FACTOR fois le plancher. La famille du plancher échoue à son propre
        test, donc s'exclut d'elle-même ;
      * le PLANCHER lui-même est ajouté au mélange, à part. Il n'est pas là pour charger : il est là
        pour mesurer ce que devient le clic instantané d'un tableau de bord quand cinq collègues
        lancent des monstres. C'est ce que l'analyste RESSENT, et aucune moyenne ne le montre.
    Une classe INSTABLE SEUL reste éligible au mélange (elle charge) mais sera hors verdict de
    justesse — les deux décisions sont indépendantes et le rapport les publie séparément."""
    usable = {k: v for k, v in probe.items() if v["p50_ms"] is not None and v["reps_ok"]}
    if not usable:
        sys.exit("aucune classe n'a répondu SEUL : rien à dériver, on refuse de charger à l'aveugle")
    floor_id = min(usable, key=lambda k: usable[k]["p50_ms"])
    floor_ms = usable[floor_id]["p50_ms"]
    per_family, rejected = {}, []
    for k, v in usable.items():
        f = family_of(k)
        if f not in per_family or v["p50_ms"] > usable[per_family[f]]["p50_ms"]:
            per_family[f] = k
    mix_ids = []
    for f in sorted(per_family):
        k = per_family[f]
        if usable[k]["p50_ms"] >= HEAVY_FACTOR * floor_ms:
            mix_ids.append(k)
        else:
            rejected.append(dict(family=f, class_id=k, p50_ms=usable[k]["p50_ms"],
                                 why=f"le plus coûteux de la famille {f} ne fait que "
                                     f"{usable[k]['p50_ms'] / floor_ms:.1f} x le plancher "
                                     f"(seuil {HEAVY_FACTOR:g})"))
    if floor_id not in mix_ids:
        mix_ids.append(floor_id)
    return dict(mix=mix_ids, floor_id=floor_id, floor_ms=floor_ms, heavy_factor=HEAVY_FACTOR,
                per_family={f: per_family[f] for f in sorted(per_family)}, rejected=rejected)


# ------------------------------------------------------------------ phase 2 : le BALAYAGE
def run_level(n, sem, mk_client, mix, win, rounds, pid, cgdir, ref, out_req, level_meta):
    """UN niveau de concurrence : `n` analystes indépendants, chacun son client HTTP (donc sa
    connexion), chacun `rounds` passages sur le mélange. Le cycle de l'analyste `i` est le mélange
    DÉCALÉ de `i` : deux voisins ne tirent pas la même requête au même instant, ce qui est le point
    même d'un mélange."""
    reqs, lock = [], threading.Lock()
    p0 = host_pressure()
    io0 = proc_io_read_bytes(pid)
    hwm0 = proc_vmhwm_bytes(pid)
    ev0 = cg_events(cgdir)
    cpu0 = time.process_time()
    smp = LoadSampler(pid, cgdir)
    smp.start()
    t0 = time.monotonic()

    def analyst(idx):
        cli = mk_client()
        for rnd in range(rounds):
            for k in range(len(mix)):
                spec = mix[(idx + k) % len(mix)]
                t_off = time.monotonic() - t0
                rec = one_request(cli, spec, win)
                rec.update(analyst=idx, round=rnd, class_id=spec["id"], kind=spec["kind"],
                           t_offset_s=round(t_off, 3), **level_meta)
                r = ref.get(spec["id"]) or {}
                # LE VERDICT DE JUSTESSE, requête par requête. `None` = hors verdict (la classe
                # n'était pas comparable SEUL), et `None` ne se compte JAMAIS comme « pareil ».
                if not r.get("stable") or rec["status"] != 200 or rec["error"]:
                    rec["same_as_solo"] = None
                else:
                    rec["same_as_solo"] = bool(rec["digest"] == r["digest"]
                                               and rec["total"] == r["total"])
                with lock:
                    reqs.append(rec)

    ths = [threading.Thread(target=analyst, args=(i,), daemon=True) for i in range(n)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    elapsed = time.monotonic() - t0
    peak_rss, peak_cg, nsamp = smp.stop()
    cpu1 = time.process_time()
    p1 = host_pressure()
    ev1 = cg_events(cgdir)
    alive = os.path.exists(f"/proc/{pid}")

    for r in reqs:
        out_req.write(json.dumps(r, ensure_ascii=False) + "\n")
    out_req.flush()

    ok = [r for r in reqs if r["status"] == 200 and not r["error"]]
    walls = [r["wall_ms"] for r in ok]
    waits = [r["sem_wait_ms"] for r in ok if r["sem_wait_ms"] is not None]
    per_analyst = []
    for i in range(n):
        w = [r["wall_ms"] for r in ok if r["analyst"] == i]
        per_analyst.append(dict(analyst=i, n=len(w), p50_ms=pctl(w, 50), p95_ms=pctl(w, 95),
                                max_ms=(max(w) if w else None)))
    per_class = {}
    for spec in mix:
        cid = spec["id"]
        w = [r["wall_ms"] for r in ok if r["class_id"] == cid]
        sw = [r["sem_wait_ms"] for r in ok if r["class_id"] == cid and r["sem_wait_ms"] is not None]
        per_class[cid] = dict(n=len(w), p50_ms=pctl(w, 50), p95_ms=pctl(w, 95),
                              max_ms=(max(w) if w else None),
                              sem_wait_p50_ms=pctl(sw, 50), sem_wait_max_ms=(max(sw) if sw else None),
                              solo_p50_ms=(ref.get(cid) or {}).get("p50_ms"))
    judged = [r for r in reqs if r["same_as_solo"] is not None]
    differs = [r for r in judged if not r["same_as_solo"]]
    faux = [r for r in differs if (ref.get(r["class_id"]) or {}).get("set_derived")]
    swap_delta = p1["swap_used_bytes"] - p0["swap_used_bytes"]
    return dict(
        analysts=n, rounds=rounds, mix=[s["id"] for s in mix],
        queries=len(reqs), queries_ok=len(ok),
        elapsed_s=round(elapsed, 3),
        throughput_qps=round(len(ok) / elapsed, 4) if elapsed > 0 else None,
        wall_p50_ms=pctl(walls, 50), wall_p95_ms=pctl(walls, 95),
        wall_max_ms=(max(walls) if walls else None),
        per_analyst=per_analyst,
        analyst_p50_min_ms=min((a["p50_ms"] for a in per_analyst if a["p50_ms"] is not None),
                               default=None),
        analyst_p50_max_ms=max((a["p50_ms"] for a in per_analyst if a["p50_ms"] is not None),
                               default=None),
        sem_wait_p50_ms=pctl(waits, 50), sem_wait_p95_ms=pctl(waits, 95),
        sem_wait_max_ms=(max(waits) if waits else None),
        sem_wait_samples=len(waits),
        # GARDE DÉRIVÉE DE LA SÉMANTIQUE D'UN SÉMAPHORE, pas d'un seuil choisi : tant qu'il y a AU
        # MOINS autant de permis que d'analystes, AUCUNE requête ne peut attendre son tour. À ces
        # niveaux, `sem_wait_ms` non nul ne PEUT PAS être de l'attente de permit — c'est donc autre
        # chose, et le nom du champ ment. On ne corrige rien ici : on MESURE l'écart et on le publie,
        # parce qu'il change entièrement la lecture des p95 sous charge.
        queue_possible=bool(n > sem),
        sem_wait_contamination_ms=(None if n > sem else (max(waits) if waits else None)),
        sem_wait_contamination_p95_ms=(None if n > sem else pctl(waits, 95)),
        per_class=per_class,
        peak_rss_bytes=peak_rss, peak_cgroup_bytes=peak_cg, rss_samples=nsamp,
        vmhwm_before_bytes=hwm0, vmhwm_after_bytes=proc_vmhwm_bytes(pid) if alive else None,
        cgroup_max_bytes=cg_int(cgdir, "memory.max"),
        cgroup_swap_max=cg_int(cgdir, "memory.swap.max"),
        cg_events_before=ev0, cg_events_after=(ev1 or None),
        # QUAND LE DAEMON EST TUÉ, SON CGROUP DISPARAÎT avec lui : `memory.events` n'est plus
        # lisible. Faire la soustraction quand même donnerait un delta NÉGATIF publié comme un
        # compteur de reclaim — un nombre faux, et le pire endroit pour en produire un, puisque
        # c'est exactement la ligne où le budget a cédé. On rend `None` et on DIT que le cgroup a
        # disparu ; l'absence est une donnée, elle n'est pas remplacée par une soustraction.
        cgroup_gone=bool(ev0 and not ev1),
        cg_events_delta=({k: ev1.get(k, 0) - ev0.get(k, 0) for k in set(ev0) | set(ev1)}
                         if ev1 else None),
        read_bytes=(proc_io_read_bytes(pid) - io0) if alive else None,
        # LE COÛT DE L'INSTRUMENT. On veut charger le DAEMON, pas la MACHINE. Si le harnais lui-même
        # brûlait une part notable des 12 cœurs, la latence mesurée serait la sienne. Publié pour
        # que le lecteur puisse le rapporter au temps mur du niveau.
        harness_cpu_s=round(cpu1 - cpu0, 3),
        harness_cpu_share=round((cpu1 - cpu0) / elapsed, 4) if elapsed > 0 else None,
        pressure_before=p0, pressure_after=p1, swap_delta_bytes=swap_delta,
        swap_suspect=bool(swap_delta > SWAP_SUSPECT_BYTES),
        justesse=dict(
            judged=len(judged), same=len(judged) - len(differs), differs=len(differs),
            nombre_faux=len(faux),
            hors_verdict=len(reqs) - len(judged),
            divergences=[dict(class_id=r["class_id"], analyst=r["analyst"], round=r["round"],
                              digest=r["digest"], total=r["total"], rows=r["rows"],
                              values=r.get("values"), served_from=r["served_from"],
                              solo_digest=(ref.get(r["class_id"]) or {}).get("digest"),
                              solo_total=(ref.get(r["class_id"]) or {}).get("total"),
                              solo_values=(ref.get(r["class_id"]) or {}).get("values"),
                              set_derived=(ref.get(r["class_id"]) or {}).get("set_derived"))
                         for r in differs][:40],
        ),
        errors=sorted({str(r["error"])[:200] for r in reqs if r["error"]}),
        statuses=sorted({r["status"] for r in reqs}),
        # LE COMPTE PAR STATUT. Un REFUS NOMMÉ (4xx : « budget 60 s dépassé ») n'est pas la même
        # chose qu'une connexion coupée (statut 0) : le premier est une dégradation MAÎTRISÉE, le
        # second est ce qui reste quand le processus n'est plus là. Les confondre dans un « échecs »
        # global effacerait la seule distinction qui compte quand le budget cède.
        status_counts={str(s): sum(1 for r in reqs if r["status"] == s)
                       for s in sorted({r["status"] for r in reqs})},
        daemon_alive=alive,
    )


# ------------------------------------------------------------------ ce que le DAEMON déclare de lui-même
def daemon_query_concurrency(admin_cli):
    """LE SÉMAPHORE EST DEMANDÉ AU DAEMON, pas prêté par l'appelant. `/api/system/diag` publie
    `PLUME_QUERY_CONCURRENCY` (allowlist non-secrète, `daemon/src/handlers/system.rs`). Une passe
    dont l'étiquette de configuration serait un simple paramètre de ligne de commande ne prouverait
    rien : c'est exactement la raison pour laquelle `run.sh` refuse déjà de mesurer une configuration
    dont l'étiquette ment. Valeur absente = variable non posée = DÉFAUT DU PRODUIT (3,
    `daemon/src/server.rs:254`), et la provenance est publiée avec le chiffre."""
    st, body = admin_cli.call("/api/system/diag")
    if st != 200 or not isinstance(body, dict):
        return None, f"/api/system/diag a répondu {st}"

    def find(o):
        if isinstance(o, dict):
            if "PLUME_QUERY_CONCURRENCY" in o:
                return o["PLUME_QUERY_CONCURRENCY"]
            for v in o.values():
                r = find(v)
                if r is not None:
                    return r
        elif isinstance(o, list):
            for v in o:
                r = find(v)
                if r is not None:
                    return r
        return None

    raw = find(body)
    if raw is None:
        return None, "/api/system/diag ne publie pas PLUME_QUERY_CONCURRENCY"
    s = str(raw).strip()
    if s == "":
        return 3, "variable non posée -> défaut du produit (server.rs:254)"
    try:
        return max(1, int(s)), "déclaré par le daemon (/api/system/diag)"
    except ValueError:
        return None, f"valeur illisible : {s!r}"


def guard_sweep(levels, sem):
    """GARDE, DÉRIVÉE DU SÉMAPHORE MESURÉ — pas une liste de niveaux autorisés.

    En dessous de la borne, aucune requête n'attend : `sem_wait_ms` est nul et la courbe ne décrit
    qu'un seul régime. La FILE ne commence qu'au-delà de la borne. Un balayage qui ne franchit pas ce
    point ne mesure donc pas la concurrence — il mesure le régime libre et l'appelle « la capacité ».
    La garde exige un point strictement EN DESSOUS et un point strictement AU-DESSUS de la valeur que
    LE DAEMON déclare. Elle n'a aucune liste : changez le sémaphore, elle change avec lui."""
    if min(levels) >= sem:
        return (f"aucun niveau strictement en dessous du sémaphore ({sem}) : sans régime libre, il "
                f"n'y a rien à quoi comparer la file")
    if max(levels) <= sem:
        return (f"aucun niveau strictement au-dessus du sémaphore ({sem}) : à {max(levels)} "
                f"analystes pour {sem} permis, aucune requête n'attend — ce balayage ne peut PAS "
                f"montrer de saturation, il mesurerait un seul régime sous un nom qui ment")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:7411")
    ap.add_argument("--host-header", default="localhost")
    ap.add_argument("--user", required=True, help="compte des REQUÊTES (viewer, comme la matrice)")
    ap.add_argument("--password", required=True)
    ap.add_argument("--admin-user", required=True, help="compte admin — sert UNIQUEMENT à demander "
                    "au daemon sa propre configuration (/api/system/diag)")
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--pid", type=int, required=True, help="PID du daemon — RSS et cgroup LUS sur lui")
    ap.add_argument("--end-ts", type=int, required=True)
    ap.add_argument("--span-days", type=int, default=28)
    ap.add_argument("--hot-window-days", type=int, default=7)
    ap.add_argument("--retention-days", type=int, default=30)
    ap.add_argument("--levels", default="1,2,3,4,6,8,10",
                    help="nombres d'analystes simultanés, croissants. La COURBE est le résultat ; "
                         "un point isolé n'en est pas un.")
    ap.add_argument("--rounds", type=int, default=2,
                    help="passages de chaque analyste sur le mélange")
    ap.add_argument("--probe-reps", type=int, default=3,
                    help="répétitions de la référence SEUL. >= 2 : c'est ce qui permet de dire "
                         "qu'une réponse est stable SANS charge avant d'accuser la concurrence.")
    ap.add_argument("--mix", default="",
                    help="IMPOSE le mélange (ids de classes, séparés par des virgules) au lieu de le "
                         "DÉRIVER de la passe solo. Sert à une seule chose, et elle est décisive : "
                         "comparer deux tailles de sémaphore n'a de sens que si les deux passes font "
                         "EXACTEMENT le même travail. La dérivation reste calculée et publiée à côté "
                         "— si elle diverge du mélange imposé, le lecteur le voit.")
    ap.add_argument("--expect-sem", type=int, default=None,
                    help="valeur ATTENDUE de PLUME_QUERY_CONCURRENCY. Si le daemon en déclare une "
                         "autre, on refuse : mesurer sous une étiquette fausse est pire que ne pas "
                         "mesurer.")
    ap.add_argument("--config-id", required=True)
    ap.add_argument("--config-meta", default="{}")
    ap.add_argument("-o", "--out", required=True, help="JSONL — une ligne par NIVEAU")
    ap.add_argument("--out-requests", required=True, help="JSONL — une ligne par REQUÊTE")
    a = ap.parse_args()

    viewer = Client(a.base, a.user, a.password, a.host_header)
    admin = Client(a.base, a.admin_user, a.admin_password, a.host_header)
    meta = json.loads(a.config_meta)

    sem, sem_src = daemon_query_concurrency(admin)
    if sem is None:
        sys.exit(f"impossible de LIRE le sémaphore sur le daemon ({sem_src}) — on refuse de publier "
                 f"une courbe de concurrence dont on ne connaît pas la borne")
    if a.expect_sem is not None and a.expect_sem != sem:
        sys.exit(f"le daemon déclare PLUME_QUERY_CONCURRENCY={sem} alors que la passe s'intitule "
                 f"{a.expect_sem} — étiquette FAUSSE, on s'arrête")
    levels = sorted({int(x) for x in a.levels.split(",") if x.strip()})
    if not levels or levels[0] < 1:
        sys.exit("--levels doit contenir au moins un entier >= 1")
    why = guard_sweep(levels, sem)
    if why:
        sys.exit(f"balayage REFUSÉ : {why}")

    # LA FENÊTRE : la plus coûteuse, et elle est DÉRIVÉE comme les autres. `windows()` marque d'une
    # portée nulle la seule fenêtre SANS borne — celle que docs/BENCHMARK.md décrit comme « le cas le
    # plus coûteux » parce qu'elle traverse tout le jeu. On la reconnaît à cette propriété, pas à son
    # nom : renommer `all` ne casserait rien ici.
    kept, _ = windows(a.end_ts, a.span_days, a.hot_window_days, a.retention_days)
    unbounded = [w for w in kept if w["frm"] == 0 and w["to"] == 0]
    if len(unbounded) != 1:
        sys.exit(f"attendu EXACTEMENT une fenêtre sans borne, {len(unbounded)} trouvée(s) — le "
                 f"harnais ne saurait pas laquelle est « le cas le plus coûteux »")
    win = unbounded[0]

    cgdir = cgroup_dir(a.pid)
    if not cgdir or cg_int(cgdir, "memory.max") is None:
        sys.exit("le daemon n'est pas dans un cgroup avec un plafond mémoire LISIBLE : le budget de "
                 "2 Gio serait SUPPOSÉ et non appliqué. On refuse (même règle que bench/run.sh).")
    mem_max, swap_max = cg_int(cgdir, "memory.max"), cg_int(cgdir, "memory.swap.max")
    if swap_max != 0:
        sys.exit(f"memory.swap.max={swap_max} : un dépassement glisserait au swap au lieu d'être un "
                 f"kill. Le budget ne serait pas appliqué — on refuse de mesurer ça.")

    classes = query_classes(a.end_ts)
    print("== mise au repos du daemon (l'ANALYZE de démarrage tient le lock writer)",
          file=sys.stderr, flush=True)
    quiet = wait_quiescent(viewer, classes[0], win)
    print(f"   au repos après {quiet['seconds']}s (quiescent={quiet['quiescent']})",
          file=sys.stderr, flush=True)
    print(f"== référence SEUL ({len(classes)} classes x {a.probe_reps}) sur la fenêtre "
          f"{win['id']} — sémaphore={sem} ({sem_src})", file=sys.stderr, flush=True)
    probe = probe_solo(viewer, classes, win, a.probe_reps)
    d = derive_mix(probe)
    by_id = {c["id"]: c for c in classes}
    # MÉLANGE IMPOSÉ : la dérivation est toujours calculée (elle reste publiée), mais c'est le
    # mélange reçu qui est TIRÉ. Sans ça, deux passes consécutives peuvent dériver deux mélanges
    # différents — il suffit que deux classes d'une même famille soient proches et que la machine
    # les départage autrement — et leur écart de débit ne serait plus attribuable au sémaphore mais
    # au travail. C'est le même principe que le témoin `chaud-seul` du tier froid : on ne change
    # qu'UNE chose à la fois.
    mix_ids = [x.strip() for x in a.mix.split(",") if x.strip()] or list(d["mix"])
    unknown = [i for i in mix_ids if i not in by_id]
    if unknown:
        sys.exit(f"--mix nomme des classes qui n'existent pas dans measure.query_classes : {unknown}")
    d["imposed"] = bool(a.mix)
    d["mix_effectif"] = mix_ids
    d["diverge_de_la_derivation"] = sorted(set(mix_ids) ^ set(d["mix"]))
    mix = [by_id[i] for i in mix_ids]
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    head = dict(phase="concurrency_probe", config_id=a.config_id, config=meta,
                query_sem=sem, query_sem_source=sem_src,
                window=win["id"], window_from=win["frm"], window_to=win["to"],
                levels=levels, rounds=a.rounds, probe_reps=a.probe_reps,
                cgroup=dict(dir=cgdir, memory_max=mem_max, memory_swap_max=swap_max),
                quiescence=quiet,
                derivation=d, solo=probe,
                # SEUL, aucune requête ne peut attendre un permit : ce maximum est, par construction,
                # de la contamination — du travail fait AVANT le permit et compté comme de l'attente.
                sem_wait_solo_max_ms=max((v["sem_wait_ms"] or 0) for v in probe.values()),
                exclus_du_verdict=[k for k, v in probe.items() if not v["stable"]],
                routes_sans_sem_wait=sorted({v["kind"] for v in probe.values()
                                             if not v["publishes_sem_wait"]}),
                classes_sans_sem_wait=sorted(k for k, v in probe.items()
                                             if not v["publishes_sem_wait"]),
                measured_at=stamp)
    with open(a.out, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(head, ensure_ascii=False) + "\n")
    print(f"== mélange {'IMPOSÉ' if d['imposed'] else 'DÉRIVÉ'} ({len(mix)}) : {', '.join(mix_ids)}\n"
          f"   dérivation : {', '.join(d['mix'])}\n"
          f"   plancher={d['floor_id']} {d['floor_ms']:.2f} ms ; seuil lourd = "
          f"{HEAVY_FACTOR:g} x plancher", file=sys.stderr, flush=True)

    rc = 0
    with open(a.out, "a", encoding="utf-8") as fh, \
            open(a.out_requests, "a", encoding="utf-8") as fq:
        for n in levels:
            lm = dict(config_id=a.config_id, query_sem=sem, level=n)
            print(f"== niveau {n} analyste(s)", file=sys.stderr, flush=True)
            row = run_level(n, sem, lambda: Client(a.base, a.user, a.password, a.host_header),
                            mix, win, a.rounds, a.pid, cgdir,
                            {k: probe[k] for k in mix_ids}, fq, lm)
            row.update(phase="concurrency", config_id=a.config_id, config=meta,
                       query_sem=sem, query_sem_source=sem_src,
                       window=win["id"], window_from=win["frm"], window_to=win["to"],
                       measured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()
            j = row["justesse"]
            nn = lambda v: -1 if v is None else v
            print(f"   {row['queries_ok']}/{row['queries']} ok en {row['elapsed_s']:.1f}s "
                  f"= {row['throughput_qps']} req/s ; "
                  f"p50={nn(row['wall_p50_ms']):.0f}ms p95={nn(row['wall_p95_ms']):.0f}ms ; "
                  f"attente p50={row['sem_wait_p50_ms']} max={row['sem_wait_max_ms']} ms ; "
                  f"rss={row['peak_rss_bytes']/2**20:.0f}Mio cgroup={row['peak_cgroup_bytes']/2**20:.0f}Mio ; "
                  f"justesse same={j['same']} differs={j['differs']} faux={j['nombre_faux']}"
                  f"{' SWAP!' if row['swap_suspect'] else ''}", file=sys.stderr, flush=True)
            if j["nombre_faux"]:
                rc = 4
            if not row["daemon_alive"]:
                # Sous `MemoryMax` sans swap, un daemon disparu est un DÉPASSEMENT DU BUDGET, pas un
                # incident de mesure. On l'écrit comme tel et on arrête : tout ce qui suivrait serait
                # un échec de connexion enregistré comme une mesure.
                fh.write(json.dumps(dict(
                    phase="concurrency", config_id=a.config_id, query_sem=sem, analysts=n,
                    daemon_died_at_level=n,
                    note=("le daemon n'existe plus après ce niveau : sous MemoryMax sans swap, "
                          "cela signifie un DÉPASSEMENT DU BUDGET (kill du noyau). Les niveaux "
                          "suivants ne sont PAS mesurés."),
                    measured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z")), ensure_ascii=False) + "\n")
                print(f"!!! daemon mort au niveau {n} — DÉPASSEMENT DU BUDGET. Arrêt.",
                      file=sys.stderr, flush=True)
                return 3
    return rc


if __name__ == "__main__":
    sys.exit(main())
