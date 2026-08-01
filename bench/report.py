#!/usr/bin/env python3
"""bench/report.py — rend les mesures brutes (JSONL) en tableau Markdown.

    python3 bench/report.py .bench/results.jsonl -o docs/BENCHMARK.md

Le rendu ne CALCULE rien qui ne soit pas dans les mesures et ne cache aucune cellule : une cellule
en erreur, tronquée, ou prise pendant que la machine swappait apparaît AVEC son défaut.
"""
import argparse
import json
import platform
import subprocess
import time

BUDGET_BYTES = 2 * 1024**3


def mib(b):
    return None if b is None else b / 2**20


def fmt_ms(v):
    if v is None:
        return "—"
    if v < 10:
        return f"{v:.1f}"
    if v < 10_000:
        return f"{v:.0f}"
    return f"{v/1000:.1f} s"


def fmt_dur(v):
    """Durée AVEC son unité, pour la prose. Les tableaux utilisent `fmt_ms` nu (leur en-tête porte
    l'unité) ; en prose l'unité doit être collée à la valeur, sinon on écrit « 15.7 s ms »."""
    if v is None:
        return "—"
    # L'unité est choisie sur la MAGNITUDE : un écart de -2 500 ms doit s'écrire « -2.5 s », pas
    # « -2500 ms » (les deltas avant/après sont signés).
    m = abs(v)
    if m < 10:
        return f"{v:.1f} ms"
    if m < 2000:
        return f"{v:.0f} ms"
    return f"{v/1000:.1f} s"


def fmt_mib(b):
    return "—" if b is None else f"{b/2**20:.0f}"


def fmt_n(n):
    return "—" if n is None else f"{n:,}".replace(",", " ")


def hw_block():
    try:
        cpu = subprocess.run(["sh", "-c", "lscpu | sed -n 's/^Model name:\\s*//p' | head -1"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        cpu = ""
    mem = 0
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal"):
                mem = int(line.split()[1]) * 1024
    except OSError:
        pass
    return {"cpu": cpu or platform.processor() or "inconnu",
            "cores": len(open("/proc/cpuinfo").read().split("processor")) - 1,
            "mem_total_bytes": mem, "kernel": platform.release()}


USER_HZ = 100.0   # /proc/stat est TOUJOURS en USER_HZ=100 (ABI du noyau), quel que soit CONFIG_HZ.


def ingest_intervals(path):
    """Lit le CSV de la sonde d'ingest et rend UN dictionnaire PAR INTERVALLE. Rien n'est lissé :
    chaque grandeur est la différence de deux compteurs cumulatifs lus dans /proc et /sys. Les
    colonnes riches (CPU, E/S, stall mémoire) peuvent manquer — un CSV d'une passe antérieure n'en a
    pas : les clés correspondantes sortent alors à None, jamais à zéro."""
    import csv as _csv
    try:
        pts = list(_csv.DictReader(open(path, encoding="utf-8")))
    except OSError:
        return []

    def g(row, key, cast=float):
        v = (row.get(key) or "").strip()
        try:
            return cast(v)
        except (TypeError, ValueError):
            return None

    out = []
    for x, y in zip(pts, pts[1:]):
        dt = g(y, "t_unix", int) - g(x, "t_unix", int)
        dn = g(y, "events", int) - g(x, "events", int)
        if not dt or dt <= 0 or dn is None or dn <= 0:
            continue
        d = {"events": g(y, "events", int), "db_bytes": g(y, "db_bytes", int),
             "rss_bytes": g(y, "rss_bytes", int), "rate": dn / dt, "dt": dt, "dn": dn,
             "loadavg1": g(y, "loadavg1"), "wal_bytes": g(y, "wal_bytes", int),
             "count_ms": g(y, "count_ms")}
        dcpu = None
        if g(x, "daemon_cpu_s") is not None and g(y, "daemon_cpu_s") is not None:
            dcpu = g(y, "daemon_cpu_s") - g(x, "daemon_cpu_s")
            d["daemon_cores"] = dcpu / dt
            d["cpu_ms_per_event"] = dcpu * 1000.0 / dn
        gcpu = None
        if g(x, "gen_cpu_s") is not None and g(y, "gen_cpu_s") is not None:
            gcpu = g(y, "gen_cpu_s") - g(x, "gen_cpu_s")
            d["gen_cores"] = gcpu / dt
        if g(x, "cpu_busy_jiffies") is not None and g(y, "cpu_busy_jiffies") is not None:
            busy = (g(y, "cpu_busy_jiffies") - g(x, "cpu_busy_jiffies")) / USER_HZ
            d["machine_cores"] = busy / dt
            if dcpu is not None:
                # « les autres » = tout ce qui a consommé du CPU sans être le daemon ni le
                # générateur. Y compris les fils NOYAU qui exécutent NOS écritures (chiffrement du
                # volume, journalisation) : ce n'est donc pas « la contention d'un tiers », c'est
                # « le CPU non facturé au daemon ». Le dire autrement serait mentir sur la cause.
                d["other_cores"] = max(busy / dt - (dcpu / dt) - ((gcpu or 0) / dt), 0.0)
        for k, col in (("read_bytes", "read_bytes"), ("write_bytes", "write_bytes"),
                       ("syscw", "syscw"), ("cg_pgmajfault", "cg_pgmajfault"),
                       ("cg_pgsteal", "cg_pgsteal"), ("cg_mem_stall_us", "cg_mem_stall_us")):
            a, b = g(x, col), g(y, col)
            if a is not None and b is not None:
                d["d_" + k] = b - a
        d["cg_mem_current"] = g(y, "cg_mem_current", int)
        out.append(d)
    return out


def repro_cmd(args):
    """Reconstruit la commande de rendu À PARTIR DES ARGUMENTS REÇUS, en repointant tout chemin hors
    dépôt vers son homologue VERSIONNÉ dans `bench/results/`. Deux raisons, toutes deux dures :
      * un chemin absolu de la machine qui a mesuré n'a rien à faire dans un document publié ;
      * une commande de reproduction doit pointer sur des fichiers que le lecteur POSSÈDE — sinon
        elle est décorative. Les données brutes sont versionnées exactement pour ça.
    Un fichier passé au rendu mais ABSENT de `bench/results/` est signalé dans la commande même,
    plutôt que réécrit en silence vers un chemin qui n'existerait pas."""
    import os as _o
    import shlex as _sh

    def vers(p):
        b = _o.path.basename(p)
        local = _o.path.join("bench", "results", b)
        return (f"bench/results/{b}", _o.path.exists(local))

    parts, missing = [], []
    for p in args.results:
        v, ok = vers(p)
        parts.append(v)
        if not ok:
            missing.append(v)
    line = ["python3 bench/report.py " + " ".join(parts) + " \\"]
    for _c in (args.ingest_curve or []):
        v, ok = vers(_c)
        line.append(f"    --ingest-curve {v} \\")
        if not ok:
            missing.append(v)
    if args.profile and args.profile != "bench/profile-prod.json":
        line.append(f"    --profile {args.profile} \\")
    if args.ref:
        line.append(f"    --ref {_sh.quote(args.ref)} \\")
    for i, c in enumerate(args.compare or []):
        line.append(f"    --compare {_sh.quote(c)} \\")
        note = (args.compare_note or [])[i] if i < len(args.compare_note or []) else None
        if note:
            # QUOTAGE SHELL, pas JSON : ces notes contiennent des accents graves. Entre guillemets
            # doubles, un lecteur qui copie-colle la commande déclencherait une substitution de
            # commande — la commande publiée doit être collable telle quelle, sans surprise.
            line.append(f"    --compare-note {_sh.quote(note)} \\")
    if args.fill_log:
        v, ok = vers(args.fill_log)
        line.append(f"    --fill-log {v} \\")
        if not ok:
            missing.append(v)
    line.append("    -o docs/BENCHMARK.md")
    if missing:
        line.append("# ATTENTION : " + ", ".join(missing) + " n'est pas (encore) versionné —")
        line.append("# la commande ci-dessus ne tournera qu'une fois ce fichier ajouté à bench/results/.")
    return line


def render_concurrency(W, conc):
    """LA COURBE DE CONCURRENCE. Rendue à partir de `bench/concurrency.py` — une ligne par NIVEAU
    (nombre d'analystes simultanés), plus une ligne d'en-tête par configuration de sémaphore.

    Ce bloc ne calcule aucun chiffre : il range ceux qui ont été mesurés. Les seuls calculs sont des
    RAPPORTS entre deux mesures de la même passe (débit rapporté au niveau 1, écart entre deux
    tailles de sémaphore), et chacun est affiché à côté de ses deux termes."""
    heads = [d for d in conc if d.get("phase") == "concurrency_probe"]
    lvls = [d for d in conc if d.get("phase") == "concurrency" and d.get("analysts") is not None
            and not d.get("daemon_died_at_level")]
    deaths = [d for d in conc if d.get("daemon_died_at_level")]
    if not lvls:
        return
    cfgs = []
    for r in lvls:
        if r["config_id"] not in cfgs:
            cfgs.append(r["config_id"])
    head_of = {h["config_id"]: h for h in heads}

    W("## La concurrence — ce que le nœud fait quand l'équipe travaille en même temps")
    W("")
    W("Tout le reste de ce document est pris **une requête à la fois** : `sem_wait_ms` y est nul par")
    W("construction, et le document le disait lui-même. Cette section mesure l'autre condition, la")
    W("vraie : plusieurs analystes qui lancent de **très grosses** requêtes en même temps, sur la")
    W("même base et sous le **même budget appliqué** de 2 Gio.")
    W("")
    W("**Un niveau** = *N* analystes indépendants (chacun sa connexion HTTP, chacun son compte")
    W("`viewer`), chacun parcourant le mélange plusieurs fois, en décalant son point de départ — deux")
    W("voisins ne tirent donc pas la même requête au même instant. Le niveau se termine quand tous ont")
    W("fini leur travail : le débit agrégé est du travail RÉELLEMENT servi, pas une extrapolation.")
    W("")
    W("**L'ordre des questions est délibéré : la justesse d'abord.** Trois défauts de correction")
    W("viennent d'être trouvés dans les chemins d'agrégat de ce produit, et aucun n'était visible sur")
    W("un banc de latence. Chaque réponse concurrente est donc comparée **par sa valeur** à la réponse")
    W("obtenue seul — même base, même binaire, même fenêtre — avant qu'on ne regarde un seul temps.")
    W("")

    # ---------------------------------------------------------------- le mélange et sa dérivation
    h0 = heads[0] if heads else None
    if h0:
        d = h0.get("derivation") or {}
        solo = h0.get("solo") or {}
        W("### Le mélange, et pourquoi c'est celui-là")
        W("")
        W(f"Le mélange n'est pas une liste de goûts : il est **dérivé de la passe solo qui le")
        W(f"précède**. Le PLANCHER est la requête la moins chère observée (`{d.get('floor_id')}`,")
        W(f"{fmt_dur(d.get('floor_ms'))}) — c'est le coût FIXE d'une requête, pas du travail de base.")
        W("Chaque **famille** de la matrice (les classes `C1`…`C6` de ce document) entre par son")
        W(f"représentant le plus coûteux, et seulement s'il coûte au moins **{d.get('heavy_factor', 0):g} ×**")
        W("le plancher. La famille du plancher échoue ainsi à son propre test et s'exclut d'elle-même.")
        W("Le plancher est ensuite ajouté **à part** : il ne charge rien, il mesure ce que devient le")
        W("clic instantané d'un tableau de bord pendant que les collègues lancent des monstres.")
        W("")
        W("| Classe retenue | Famille | Ce que c'est | Coût SEUL (p50) |")
        W("|---|:--:|---|---:|")
        for cid in (d.get("mix_effectif") or d.get("mix") or []):
            s = solo.get(cid) or {}
            fam = cid[1] if len(cid) > 1 else "?"
            W(f"| `{cid}` | {fam} | {s.get('label','—')} | {fmt_ms(s.get('p50_ms'))} ms |")
        W("")
        if d.get("rejected"):
            W("Familles **écartées** du mélange lourd, avec leur motif mesuré :")
            W("")
            for r in d["rejected"]:
                W(f"- famille {r['family']} (`{r['class_id']}`) : {r['why']}.")
            W("")
        q = h0.get("quiescence") or {}
        if q:
            W(f"**Mise au repos avant de mesurer** : un daemon qui vient de démarrer lance un `ANALYZE`")
            W(f"complet en arrière-plan qui prend le verrou d'écriture, et le chemin interactif consulte")
            W(f"la base AVANT de prendre son permit — mesurer tout de suite, c'est mesurer le démarrage.")
            W(f"Le harnais attend donc {q.get('need')} tirs consécutifs dont l'attente avant moteur est")
            W(f"sous la milliseconde : **{fmt_dur((q.get('seconds') or 0) * 1000)}** ici")
            W(f"(`quiescent={str(q.get('quiescent')).lower()}`).")
            W("")

    # ---------------------------------------------------------------- la courbe, par sémaphore
    for c in cfgs:
        rows = sorted([r for r in lvls if r["config_id"] == c], key=lambda r: r["analysts"])
        h = head_of.get(c) or {}
        sem = rows[0].get("query_sem")
        W(f"### La courbe — `{c}` (`PLUME_QUERY_CONCURRENCY={sem}`)")
        W("")
        W(f"Sémaphore **{sem}**, {h.get('query_sem_source', 'source inconnue')}. Fenêtre "
          f"`{rows[0].get('window')}` (sans borne : le cas le plus coûteux). "
          f"{rows[0].get('rounds')} passages par analyste sur "
          f"{len(rows[0].get('mix') or [])} classes.")
        W("")
        _d = h.get("derivation") or {}
        if _d.get("imposed"):
            _dv = _d.get("diverge_de_la_derivation") or []
            W("Mélange **IMPOSÉ** (celui de la passe de référence), pour que la comparaison entre "
              "sémaphores ne porte que sur le sémaphore."
              + (f" Sa propre passe solo aurait dérivé un mélange différent de "
                 f"{len(_dv)} classe(s) : {', '.join('`' + x + '`' for x in _dv)} — "
                 f"c'est précisément ce que l'imposition neutralise." if _dv else
                 " Sa propre passe solo aurait dérivé exactement le même."))
            W("")
        elif h.get("derivation"):
            W("Mélange **DÉRIVÉ** par la passe solo de cette configuration (tableau plus haut).")
            W("")
        W("| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente p50 | attente p95 | RSS crête | plafond touché | OOM |")
        W("|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|")
        base_q = rows[0].get("throughput_qps") or 0
        for r in rows:
            ev = r.get("cg_events_delta")
            _q = r.get("throughput_qps") or 0
            _rel = "" if not base_q else f" (x{_q/base_q:.2f})"
            # Le cgroup a disparu avec le processus tué : on n'invente pas la valeur, on dit qu'elle
            # n'existe plus. Une case « — » est une absence ; un 0 serait un mensonge.
            _recl = fmt_n(ev.get("max")) if ev else ("— (cgroup disparu)" if r.get("cgroup_gone") else "—")
            _dead = "" if r.get("daemon_alive", True) else " — **daemon TUÉ**"
            W(f"| **{r['analysts']}** | {'oui' if r.get('queue_possible') else 'non'} "
              f"| {r['queries_ok']}/{r['queries']}{_dead} | {r['elapsed_s']:.0f} s "
              f"| {_q:.2f} q/s{_rel} "
              f"| {fmt_ms(r.get('wall_p50_ms'))} | {fmt_ms(r.get('wall_p95_ms'))} "
              f"| {fmt_ms(r.get('wall_max_ms'))} | {fmt_ms(r.get('analyst_p50_max_ms'))} "
              f"| {fmt_ms(r.get('sem_wait_p50_ms'))} | {fmt_ms(r.get('sem_wait_p95_ms'))} "
              f"| {fmt_mib(r.get('peak_rss_bytes'))} Mio | {_recl} "
              f"| {'**OUI**' if (ev or {}).get('oom_kill') else 'non'} |")
        W("")
        # CE QUI EST ARRIVÉ AUX REQUÊTES QUI N'ONT PAS ABOUTI. Un refus NOMMÉ et une connexion coupée
        # ne se rangent pas ensemble : le premier est une dégradation maîtrisée, le second est
        # l'absence de processus.
        bad = [r for r in rows if r["queries_ok"] < r["queries"]]
        if bad:
            W("Requêtes qui n'ont pas abouti, par statut HTTP :")
            W("")
            W("| Analystes | statuts | messages |")
            W("|---:|---|---|")
            for r in bad:
                sc = r.get("status_counts") or {}
                W(f"| {r['analysts']} | "
                  + ", ".join(f"`{k}` x{v}" for k, v in sorted(sc.items())) + " | "
                  + "<br>".join(f"`{e[:110]}`" for e in (r.get("errors") or [])[:3]) + " |")
            W("")
            W("`0` = pas de réponse HTTP du tout (connexion coupée / refusée) : c'est ce que voit un")
            W("client quand le processus n'est plus là. Un `4xx` avec une cause nommée est l'inverse :")
            W("le daemon a REFUSÉ proprement, en disant pourquoi.")
            W("")
        W("Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde")
        W("(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur")
        W("**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians")
        W("individuels — c'est lui qui dit si la charge est équitable ; *plafond touché* est le")
        W("compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû")
        W("récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.")
        W("")
        sw = [r for r in rows if r.get("swap_suspect")]
        if sw:
            W(f"**{len(sw)} niveau(x) pris pendant que la MACHINE swappait** "
              f"({', '.join(str(r['analysts']) for r in sw)} analystes) : ces lignes mesurent le")
            W("stockage de l'hôte autant que plume, elles sont à rejouer.")
            W("")
        cpu = max((r.get("harness_cpu_share") or 0) for r in rows)
        W(f"*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de")
        W(f"**{cpu*100:.1f} %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence")
        W(f"mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio")
        W(f"sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).")
        W("")

    # ---------------------------------------------------------------- justesse
    W("### La réponse est-elle la MÊME sous charge ?")
    W("")
    tot = dict(judged=0, same=0, differs=0, nombre_faux=0, hors_verdict=0)
    for r in lvls:
        j = r.get("justesse") or {}
        for k in tot:
            tot[k] += j.get(k, 0) or 0
    W("| | |")
    W("|---|---:|")
    W(f"| Réponses comparées à leur référence solo | **{fmt_n(tot['judged'])}** |")
    W(f"| Identiques (empreinte ET total) | **{fmt_n(tot['same'])}** |")
    W(f"| Divergentes | **{fmt_n(tot['differs'])}** |")
    W(f"| Dont NOMBRES FAUX (valeur dérivée d'un ensemble) | **{fmt_n(tot['nombre_faux'])}** |")
    tot_fail = sum(r["queries"] - r["queries_ok"] for r in lvls)
    W(f"| Hors verdict (voir ci-dessous) | {fmt_n(tot['hors_verdict'])} |")
    W("")
    if tot["hors_verdict"]:
        if tot["hors_verdict"] == tot_fail:
            W(f"Les {fmt_n(tot['hors_verdict'])} réponses hors verdict sont EXACTEMENT les "
              f"{fmt_n(tot_fail)} requêtes qui n'ont pas abouti (connexion coupée après le kill, ou "
              "refus nommé) : une requête sans réponse n'a rien à comparer. Aucune n'est hors verdict "
              "pour cause d'instabilité — le compte le prouve, il n'est pas affirmé.")
        else:
            W(f"Sur {fmt_n(tot['hors_verdict'])} réponses hors verdict, {fmt_n(tot_fail)} sont des "
              "requêtes qui n'ont pas abouti (rien à comparer) ; le reste vient des classes déclarées "
              "instables SEUL (voir ci-dessous).")
        W("")
    if tot["differs"] == 0:
        W("**Aucune réponse concurrente ne diffère de la réponse obtenue seul.** L'empreinte est")
        W("insensible à l'ordre (un `GROUP BY` est un sac non ordonné) et le total de pagination est")
        W("comparé en plus. Ce n'est pas une déduction depuis les latences : ce sont les VALEURS qui")
        W("ont été comparées, requête par requête, contre une référence prise sur la même base et le")
        W("même binaire quelques minutes plus tôt.")
    else:
        W("**Des réponses concurrentes diffèrent de la réponse obtenue seul.** Le détail est dans le")
        W("JSONL (`justesse.divergences` : empreinte et valeurs des deux côtés) :")
        W("")
        W("| Passe | Analystes | Classe | Dérivée d'un ensemble | Solo | Sous charge |")
        W("|---|---:|---|:--:|---|---|")
        for r in lvls:
            for dv in ((r.get("justesse") or {}).get("divergences") or [])[:8]:
                W(f"| `{r['config_id']}` | {r['analysts']} | `{dv['class_id']}` | "
                  f"{'**OUI**' if dv.get('set_derived') else 'non'} | "
                  f"`{str(dv.get('solo_values') or dv.get('solo_digest'))[:60]}` | "
                  f"`{str(dv.get('values') or dv.get('digest'))[:60]}` |")
    W("")
    excl = sorted({x for h in heads for x in (h.get("exclus_du_verdict") or [])})
    if excl:
        W("**Hors verdict, et pourquoi** : une classe dont la réponse varie DÉJÀ sans charge ne peut")
        W("pas servir à accuser la concurrence — l'accuser d'une divergence qu'on observe seul serait")
        W("une fausse alerte, et une fausse alerte détruit la valeur des vraies. Classes retirées du")
        W(f"verdict : {', '.join('`' + x + '`' for x in excl)}.")
    else:
        W("**Aucune classe n'a été retirée du verdict** : chacune rend la même réponse à chacune de ses")
        W("répétitions SEUL, donc chacune est comparable sous charge. C'est vérifié, pas supposé.")
    W("")

    # ---------------------------------------------------------------- sem_wait
    W("### `sem_wait_ms` ne mesure pas l'attente du sémaphore")
    W("")
    W("C'est le champ que le daemon publie pour séparer « la requête est lente » de « la requête")
    W("attendait son tour ». **La mesure montre qu'il ne le fait pas.**")
    W("")
    W("La démonstration ne demande aucun seuil : tant qu'il y a **au moins autant de permis que")
    W("d'analystes**, aucune requête ne peut attendre son tour. À ces niveaux, `sem_wait_ms` doit être")
    W("nul par construction. Mesuré :")
    W("")
    W("| Passe | Analystes | Permis | File possible ? | `sem_wait_ms` p95 | `sem_wait_ms` max |")
    W("|---|---:|---:|:--:|---:|---:|")
    contam = []
    for r in lvls:
        if r.get("queue_possible"):
            continue
        contam.append(r)
        W(f"| `{r['config_id']}` | {r['analysts']} | {r.get('query_sem')} | **non** | "
          f"{fmt_ms(r.get('sem_wait_contamination_p95_ms'))} | "
          f"**{fmt_ms(r.get('sem_wait_contamination_ms'))}** |")
    W("")
    worst = max((r.get("sem_wait_contamination_ms") or 0) for r in contam) if contam else 0
    solo_worst = max((h.get("sem_wait_solo_max_ms") or 0) for h in heads) if heads else 0
    if worst > 1 or solo_worst > 1:
        W(f"Le maximum observé **là où aucune file n'est possible** est de **{fmt_dur(worst)}** en")
        W(f"charge sous-critique, et de **{fmt_dur(solo_worst)}** pendant la passe solo (un seul")
        W("client, aucun autre en vol). Un sémaphore avec des permis libres ne peut pas produire ça.")
        W("")
        W("**Ce que le champ mesure réellement** : le chrono démarre à l'entrée du handler")
        W("(`daemon/src/handlers/query.rs:362`) et n'est lu qu'APRÈS le permit (`:556`, `sem_wait_ms`")
        W("posé en `:560`). Entre les deux, la requête résout les masques de champs et lit la")
        W("**couverture des rollups** — et cette lecture prend le verrou de la connexion PARTAGÉE")
        W("(`:479`, `req_db(...).lock()`), celui-là même que tiennent les travaux de fond (`ANALYZE`")
        W("de démarrage, boucle de rollups). `sem_wait_ms` additionne donc **l'attente du permit ET")
        W("une attente de verrou qui n'est bornée par aucun sémaphore** — un point de sérialisation")
        W("qui, lui, existe AVANT la borne de concurrence et n'est mesuré nulle part. Conséquence")
        W("directe sur la lecture de ce document : un `sem_wait_ms` élevé ne prouve PAS que le")
        W("sémaphore est trop petit — il faut regarder le niveau, et savoir si une file y était")
        W("seulement possible. C'est pour cela que la colonne « file possible » existe.")
    else:
        W("Aucune contamination mesurée : là où aucune file n'est possible, l'attente publiée est")
        W("nulle. Le champ mesure donc bien ce que son nom dit, sur cette passe.")
    W("")
    nosw = sorted({x for h in heads for x in (h.get("classes_sans_sem_wait") or [])})
    if nosw:
        W(f"**Angle mort restant** : {', '.join('`' + x + '`' for x in nosw)} ne publie(nt) aucun")
        W("`stats` — la barre `/api/search` prend pourtant un permit sur le MÊME sémaphore. Sur cette")
        W("route, il est donc impossible de distinguer une recherche lente d'une recherche qui")
        W("attendait : c'est mesuré ici, ce n'est pas corrigé ici.")
        W("")

    # ---------------------------------------------------------------- le clic sous charge
    floor_id = (h0.get("derivation") or {}).get("floor_id") if h0 else None
    if floor_id:
        W("### Le clic de tableau de bord, pendant que les autres travaillent")
        W("")
        W(f"`{floor_id}` est la requête la moins chère de la matrice. Seule, elle est instantanée. Ce")
        W("tableau est ce que l'analyste RESSENT : aucune moyenne ne le montre, parce qu'elle est")
        W("noyée dans les monstres.")
        W("")
        W("| Passe | Analystes | p50 | p95 | pire |")
        W("|---|---:|---:|---:|---:|")
        for r in lvls:
            pc = (r.get("per_class") or {}).get(floor_id) or {}
            W(f"| `{r['config_id']}` | {r['analysts']} | {fmt_ms(pc.get('p50_ms'))} | "
              f"{fmt_ms(pc.get('p95_ms'))} | {fmt_ms(pc.get('max_ms'))} |")
        W("")

    # ---------------------------------------------------------------- budget
    W("### Le budget de 2 Gio, à plusieurs")
    W("")
    peak = max((r.get("peak_rss_bytes") or 0) for r in lvls)
    cgpeak = max((r.get("peak_cgroup_bytes") or 0) for r in lvls)
    cgmax = max((r.get("cgroup_max_bytes") or 0) for r in lvls)
    ooms = sum((r.get("cg_events_delta") or {}).get("oom_kill", 0) or 0 for r in lvls)
    killed = [r for r in lvls if not r.get("daemon_alive", True)]
    W(f"- **RSS crête du daemon, tous niveaux confondus : {fmt_mib(peak)} Mio** "
      f"({peak/BUDGET_BYTES*100:.0f} % du budget).")
    W(f"- **Mémoire du cgroup crête : {fmt_mib(cgpeak)} Mio** pour un plafond de {fmt_mib(cgmax)} Mio.")
    W("  Ce n'est pas la même grandeur que la RSS : le noyau compare au plafond la mémoire du CGROUP,")
    W("  cache de pages compris. Une base de 1,4 Gio lue en boucle le remplit — le cgroup vit donc")
    W("  **collé à son plafond**, et ce qui varie n'est pas son occupation mais son travail de")
    W("  récupération.")
    if killed:
        for r in killed:
            # Le plafond du cgroup n'est plus lisible sur le niveau qui a tué le processus (le cgroup
            # est parti avec lui) : on reprend celui des autres niveaux de LA MÊME passe, qui est le
            # même scope et le même réglage. Publier « — » ici cacherait le seul terme de comparaison.
            _cm = max((x.get("cgroup_max_bytes") or 0) for x in lvls
                      if x["config_id"] == r["config_id"]) or None
            W(f"- **LE BUDGET A CÉDÉ** : `{r['config_id']}`, **{r['analysts']} analystes** "
              f"(sémaphore {r.get('query_sem')}). RSS crête {fmt_mib(r.get('peak_rss_bytes'))} Mio "
              f"contre un plafond de {fmt_mib(_cm)} Mio, "
              f"{r['queries'] - r['queries_ok']} requêtes sur {r['queries']} n'ont pas abouti, et le "
              f"processus n'existait plus à la fin du niveau. Sous `MemoryMax` **sans swap**, cela ne "
              f"peut pas être autre chose qu'un dépassement du budget : le noyau tue, il ne glisse "
              f"pas en swap. Les niveaux au-delà ne sont **pas** mesurés — une absence, pas un zéro.")
        W("- La dégradation n'est pas binaire : AVANT le kill, le daemon a d'abord REFUSÉ proprement "
          "des requêtes en nommant sa cause (budget interactif de 60 s dépassé, `4xx`). Le refus "
          "nommé arrive donc en premier ; le kill est ce qui suit quand la mémoire, elle, ne "
          "négocie pas.")
    W(f"- **Tués par le noyau (`memory.events:oom_kill`) : {ooms}** — compteur du cgroup, à lire avec "
      "la réserve ci-dessus : le cgroup d'un scope tué disparaît avec lui, et son compteur n'est "
      "alors plus lisible du tout.")
    if deaths:
        for d in deaths:
            W(f"- Le harnais a ARRÊTÉ le balayage après le niveau {d['daemon_died_at_level']} "
              f"(`{d.get('config_id')}`) : {d['note']}")
    if not killed:
        W("- **Le daemon n'a été tué à aucun niveau mesuré.** Le dépassement du budget ne se manifeste")
        W("  donc pas ici par un kill mais par du **travail de récupération** : la colonne « plafond")
        W("  touché » des courbes ci-dessus compte, pour chaque niveau, le nombre de fois où le noyau")
        W("  a dû reprendre de la mémoire au cgroup pour rester sous 2 Gio.")
    W("")

    # ---------------------------------------------------------------- l'échange sémaphore <-> RAM
    # GARDE DE COMPARABILITÉ, DÉRIVÉE DES DONNÉES : deux passes ne peuvent être comparées en DÉBIT
    # que si elles ont fait EXACTEMENT le même travail. Le mélange est enregistré dans chaque ligne
    # de niveau ; on ne compare donc que les configurations dont le mélange est identique, et on
    # NOMME celles qu'on écarte. Sans cette garde, une différence de mélange (deux classes proches
    # d'une même famille départagées autrement) se lirait comme un effet du sémaphore.
    groups = {}
    for c in cfgs:
        key = tuple((next(r for r in lvls if r["config_id"] == c).get("mix") or []))
        groups.setdefault(key, []).append(c)
    best = max(groups.values(), key=len) if groups else []
    excluded_cfgs = [c for c in cfgs if c not in best]
    if len(best) > 1:
        cfgs = best
        W("### Ce que coûte, et ce que rapporte, la taille du sémaphore")
        W("")
        W("Le sémaphore de l'interactif est à 3 par défaut, après avoir été baissé depuis 8 **comme")
        W("levier de RAM**. Les passes comparées ici tournent sur la MÊME base, la MÊME machine, le")
        W("MÊME binaire **et le MÊME mélange de requêtes** : leur écart, à niveau d'analystes égal,")
        W("EST le taux de change entre concurrence et mémoire.")
        W("")
        W("**Il est réglable sans recompiler** : `PLUME_QUERY_CONCURRENCY` est lu dans la")
        W("configuration au démarrage (`daemon/src/server.rs:254`, défaut 3) et le daemon publie la")
        W("valeur qu'il applique sur `/api/system/diag` — c'est de là que ce banc la lit, plutôt que")
        W("de la supposer. En revanche il est lu **une seule fois, au boot** : le changer demande un")
        W("redémarrage, et un redémarrage a son propre coût (voir la mise au repos plus haut).")
        W("")
        if excluded_cfgs:
            W(f"**Écartée(s) de cette comparaison** : {', '.join('`' + c + '`' for c in excluded_cfgs)}")
            W("— leur mélange n'est pas celui des autres passes, donc leur écart de débit ne serait pas")
            W("attribuable au sémaphore mais au travail. Leur courbe reste publiée plus haut ; c'est")
            W("cette comparaison-ci, et elle seule, qui exige un travail identique.")
            W("")
        W("| Analystes | " + " | ".join(f"débit `{c}`" for c in cfgs) + " | écart de débit | "
          + " | ".join(f"p95 `{c}`" for c in cfgs) + " | "
          + " | ".join(f"RSS `{c}`" for c in cfgs) + " |")
        W("|---:|" + "---:|" * (len(cfgs) * 3 + 1))
        by = {}
        for r in lvls:
            if r["config_id"] in cfgs:
                by.setdefault(r["analysts"], {})[r["config_id"]] = r
        for n in sorted(by):
            got = by[n]
            if len(got) < len(cfgs):
                continue
            qs = [got[c].get("throughput_qps") or 0 for c in cfgs]
            gain = "—" if not qs[0] else f"x{qs[-1]/qs[0]:.2f}"
            W(f"| **{n}** | " + " | ".join(f"{q:.2f} q/s" for q in qs) + f" | {gain} | "
              + " | ".join(fmt_ms(got[c].get("wall_p95_ms")) for c in cfgs) + " | "
              + " | ".join(fmt_mib(got[c].get("peak_rss_bytes")) + " Mio" for c in cfgs) + " |")
        W("")
        # CE QUE LES DEUX COLONNES DISENT, calculé DEPUIS le tableau ci-dessus et nulle part ailleurs.
        # Le niveau retenu est le plus chargé mesuré des DEUX côtés : c'est là que l'écart de
        # sémaphore a le plus de chances de se voir, donc le cas le plus favorable au grand
        # sémaphore. S'il n'y gagne pas, il ne gagne nulle part.
        common = [n for n in sorted(by) if len(by[n]) == len(cfgs)]
        if common:
            n = common[-1]
            g = by[n]
            q0 = g[cfgs[0]].get("throughput_qps") or 0
            q1 = g[cfgs[-1]].get("throughput_qps") or 0
            r0 = g[cfgs[0]].get("peak_rss_bytes") or 0
            r1 = g[cfgs[-1]].get("peak_rss_bytes") or 0
            p0 = g[cfgs[0]].get("wall_p95_ms")
            p1 = g[cfgs[-1]].get("wall_p95_ms")
            W(f"**Au niveau le plus chargé mesuré des deux côtés ({n} analystes)** : "
              f"{q1:.2f} contre {q0:.2f} requête/s "
              + (f"(**{(q1/q0-1)*100:+.0f} %** de travail servi)" if q0 else "") + ", "
              f"p95 {fmt_dur(p1)} contre {fmt_dur(p0)}, RSS crête {fmt_mib(r1)} contre "
              f"{fmt_mib(r0)} Mio (**{(r1-r0)/2**20:+.0f} Mio**, soit "
              f"{(r1-r0)/BUDGET_BYTES*100:+.1f} % du budget). Ces six nombres SONT le taux de change "
              f"entre un sémaphore à {g[cfgs[0]].get('query_sem')} et un sémaphore à "
              f"{g[cfgs[-1]].get('query_sem')} — celui que la baisse de 8 à 3, faite comme levier de "
              f"RAM, avait acheté sans jamais être chiffré.")
            W("")
    elif len(cfgs) > 1:
        W("### Ce que coûte, et ce que rapporte, la taille du sémaphore")
        W("")
        W("**Pas de comparaison publiée.** Les passes mesurées n'ont pas tiré le MÊME mélange de")
        W("requêtes : leur écart de débit mélangerait l'effet du sémaphore et celui du travail. Un")
        W("banc ne change qu'une chose à la fois — les courbes restent publiées séparément.")
        W("")


def _cmp_load(eff, cfg):
    """Charge machine (loadavg 1 min) relevée PENDANT une passe : min-max sur ses cellules. Sans elle,
    un écart de latence entre deux passes pourrait n'être qu'un écart de charge."""
    v = [(r.get("pressure_before") or {}).get("loadavg", [None])[0]
         for r in eff if r["config_id"] == cfg]
    v = [x for x in v if x is not None]
    if not v:
        return "non relevé"
    return f"{min(v):.1f}–{max(v):.1f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+",
                    help="un ou plusieurs JSONL. Plusieurs volumes -> le tableau d'échelle "
                         "s'active. Aucune fusion de cellules : chaque fichier garde ses "
                         "étiquettes de configuration.")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--profile", default="bench/profile-prod.json")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--fill-log", default=None,
                    help="journal d'une passe run.sh : les lignes de progression du générateur "
                         "(« N événements … R ev/s produits ») sont du DÉBIT MESURÉ de bout en bout, "
                         "et couvrent le début du remplissage que l'échantillonneur peut manquer")
    ap.add_argument("--ref", default=None, metavar="CONFIG_ID",
                    help="configuration qui sert de RÉFÉRENCE au verdict et aux leviers. Par défaut : "
                         "FTS off + masque vide, au plus gros volume, et à volume égal la plus "
                         "récemment mesurée. À poser EXPLICITEMENT quand plusieurs passes coexistent "
                         "au même volume — sinon le document pourrait décrire une passe prise sur une "
                         "version du code qui n'est plus celle du dépôt.")
    ap.add_argument("--compare", action="append", metavar="AVANT:APRES",
                    help="deux étiquettes de configuration : rend un tableau d'ÉCART cellule par "
                         "cellule (avant, après, delta). Sert à publier ce qu'un correctif a changé "
                         "SANS reformuler les tableaux — chaque ligne reste une mesure.")
    ap.add_argument("--compare-note", action="append",
                    help="ce qui a changé entre les deux configurations comparées (une phrase). "
                         "Rendu tel quel : sans lui, le tableau d'écart ne dit pas ce qu'il mesure.")
    ap.add_argument("--ingest-curve", action="append",
                    help="CSV t_unix,events,db_bytes,rss_bytes,loadavg1 échantillonné pendant "
                         "l'ingest : rend la COURBE de débit en fonction du volume déjà en base")
    args = ap.parse_args()

    rows, ingest, deaths, unmeasured_win, conc = [], [], [], [], []
    for path in args.results:
      with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if d.get("daemon_died_after_this_cell"):
                deaths.append(d)
            elif d.get("window_not_measured"):
                # Une fenêtre ÉCARTÉE par la garde de couverture du harnais. Elle n'est pas une
                # cellule : elle est une ABSENCE, et elle est publiée comme telle.
                unmeasured_win.append(d)
            elif str(d.get("phase") or "").startswith("concurrency") or "analyst" in d:
                # LA CONCURRENCE a ses propres lignes : un NIVEAU (N analystes) n'est pas une cellule
                # de la matrice et n'a ni classe ni fenêtre unique. La ranger avec les cellules
                # ferait entrer des lignes sans `class_id` dans tous les tableaux.
                # Le second critère (`analyst`) attrape le JSONL des REQUÊTES INDIVIDUELLES, qui est
                # une donnée brute publiée : il est reconnu à sa FORME (une requête appartient à un
                # analyste), pas à une étiquette — le passer au rendu ne peut donc pas le casser.
                conc.append(d)
            elif d.get("phase") in ("ingest", "cold_age") or str(d.get("phase") or "").startswith("cold_parity"):
                ingest.append(d)
            else:
                rows.append(d)
    if not rows:
        raise SystemExit("aucune cellule de mesure dans " + " ".join(args.results))

    hw = hw_block()
    configs, cfgmeta = [], {}
    for r in rows:
        if r["config_id"] not in configs:
            configs.append(r["config_id"])
            cfgmeta[r["config_id"]] = r.get("config") or {}
    # Dédoublonnage par class_id SEUL : un libellé retouché entre deux passes ne doit pas faire
    # apparaître la même classe deux fois dans les tableaux. Le libellé retenu est le plus récent.
    classes, _seen = [], {}
    for r in rows:
        cid = r["class_id"]
        if cid not in _seen:
            _seen[cid] = len(classes)
            classes.append((cid, r["label"], r["kind"]))
        else:
            classes[_seen[cid]] = (cid, r["label"], r["kind"])
    # Les fenêtres sont DÉRIVÉES des cellules présentes, jamais écrites en dur : le harnais les
    # dérive lui-même de l'étendue du jeu et de la fenêtre chaude du produit
    # (`PLUME_COLD_HOT_WINDOW_DAYS`), donc une passe faite avec une autre fenêtre chaude rend son
    # propre tableau. L'ordre est chronologique (portée croissante), `tout` en dernier.
    def _win_key(w):
        if w == "all":
            return (9e18, w)
        if w.endswith("h"):
            return (float(w[:-1]) * 3600, w)
        if w.startswith("au-dela-"):
            return (8e18, w)      # bande la plus ancienne : juste avant `tout`
        if w.endswith("d"):
            return (float(w[:-1]) * 86400, w)
        return (7e18, w)
    wins = sorted({r["window"] for r in rows}, key=_win_key)
    # Une cellule rejouée (parce qu'elle avait été prise sous swap, par exemple) écrit une SECONDE
    # ligne pour la même clé. La dernière écrite gagne : c'est la mesure valide. Les verdicts sont
    # donc calculés sur les cellules EFFECTIVES, pas sur l'historique — sinon une cellule corrigée
    # continuerait d'être comptée comme fausse. Le nombre de cellules remplacées est publié.
    idx = {}
    superseded = 0
    for r in rows:
        k = (r["config_id"], r["class_id"], r["window"])
        if k in idx:
            superseded += 1
        idx[k] = r
    eff = list(idx.values())

    over = [r for r in eff if (r.get("peak_rss_bytes") or 0) > BUDGET_BYTES]
    swapped = [r for r in eff if r.get("swap_suspect")]
    failed = [r for r in eff if r.get("reps_ok", 0) == 0 or r.get("errors")]
    truncated = [r for r in eff if r.get("truncated")]

    L = []
    W = L.append
    W("# Banc de mesure plume — requêtes à chaud sous 2 Gio")
    W("")
    W("<!-- CE FICHIER EST GÉNÉRÉ par bench/report.py (voir la section « Reproduire » en bas).")
    W("     Ne pas l'éditer à la main : la prochaine passe l'écrase. Tout commentaire durable va dans")
    W("     bench/README.md. -->")
    W("")
    import os as _os
    # Les données BRUTES sont VERSIONNÉES dans `bench/results/`. C'est ce qui rend ce document
    # RÉFUTABLE : sans elles, un lecteur ne peut que croire le tableau ou l'ignorer. Elles ont été
    # scannées avant publication (270 + ~80 lignes JSON : chemins personnels, e-mails, jetons, IP hors
    # plages de documentation, hexadécimal long — ZÉRO correspondance ; les seules requêtes qui y
    # figurent sont celles du banc, synthétiques).
    W(f"Rendu le {time.strftime('%Y-%m-%d %H:%M:%S%z')} depuis "
      + ", ".join(f"`{_os.path.basename(p)}`" for p in args.results)
      + " — données brutes VERSIONNÉES dans [`bench/results/`](../bench/results/), pour que ce"
      + " tableau puisse être contredit et pas seulement cru (cf. `bench/README.md`).")
    W("")
    W("## Ce que ce document est, et ce qu'il n'est pas")
    W("")
    W("C'est la **mesure de référence** de plume, prise avec un instrument publié et rejouable.")
    W("Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est une case")
    W("**non mesurée**, pas une case implicitement bonne. Quand plusieurs passes coexistent au même")
    W("volume, elles sont TOUTES rendues : une passe n'est jamais remplacée par une plus flatteuse,")
    W("et la section « Écart mesuré entre deux passes » dit laquelle décrit le code actuel.")
    W("")
    W("Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : c'est un")
    W("banc synthétique au **profil** de la production (voir `bench/profile-prod.json`).")
    W("")

    # ------------------------------------------------------------ VERDICT, calculé sur les mesures
    # La raison d'être du document : dire ce que les mesures AUTORISENT à affirmer et ce qu'elles
    # n'autorisent pas. Tout ici est dérivé des cellules, aucune phrase n'est un jugement libre.
    def _nev0(c):
        return (cfgmeta[c].get("events") or 0)
    # À volume ÉGAL, la configuration la PLUS RÉCEMMENT mesurée gagne (dernière apparition dans le
    # JSONL). Sans ce départage, une passe de RE-mesure après correctif serait ignorée et le document
    # continuerait à décrire un état du code déjà corrigé.
    _cands0 = [c for c in configs if cfgmeta[c].get("fts_fields") == 0
               and "non-vide" not in (cfgmeta[c].get("mask") or "")] or configs
    if args.ref:
        if args.ref not in configs:
            raise SystemExit(f"--ref : configuration absente des résultats : {args.ref}")
        ref = args.ref
    else:
        ref = max(_cands0, key=lambda c: (_nev0(c), configs.index(c)))
    ref_rows = [r for r in eff if r["config_id"] == ref and r.get("wall_p50_ms") is not None]
    peak_all = max((r.get("peak_rss_bytes") or 0) for r in rows)
    fast = sorted(ref_rows, key=lambda r: r["wall_p50_ms"])[:4]
    slow = sorted(ref_rows, key=lambda r: -r["wall_p50_ms"])[:4]
    W("## Verdict — ce que ces mesures autorisent à affirmer")
    W("")
    W(f"Volume de référence : **{fmt_n(_nev0(ref))} événements** (`{ref}`), base "
      f"**{fmt_mib(cfgmeta[ref].get('db_bytes'))} Mio** chiffrée SQLCipher.")
    W("")
    W("**Sur le budget de 2 Gio — soutenu.** RSS crête la plus haute mesurée sur l'ensemble des "
      f"cellules : **{fmt_mib(peak_all)} Mio**, soit **{peak_all/BUDGET_BYTES*100:.0f} %** du "
      "budget. Et ce n'est pas une observation passive : le daemon tournait sous "
      "`MemoryMax=2G MemorySwapMax=0`, où un dépassement est un kill du noyau.")
    W("")
    W("**Ce qui est RAPIDE** (p50, fenêtre indiquée, config de référence) :")
    W("")
    for r in fast:
        W(f"- `{r['class_id']}` / {r['window']} — **{fmt_dur(r['wall_p50_ms'])}** "
          f"({r['label']}), servi par `{r.get('served_from') or 'scan'}`")
    W("")
    fl0 = idx.get((ref, "C0-plancher", "all")) or idx.get((ref, "C0-plancher", "1h"))
    if fl0 and fl0.get("wall_p50_ms") is not None \
            and (fl0["wall_p50_ms"] - (fl0.get("sql_p50_ms") or 0)) > 10.0:
        W(f"Toutes ces cellules sont AU PLANCHER. Une requête dont le SQL ne coûte rien revient en "
          f"**{fmt_dur(fl0['wall_p50_ms'])}** (`C0-plancher`, SQL mesuré à "
          f"{fmt_dur(fl0.get('sql_p50_ms'))}) : c'est un coût FIXE, indépendant du volume, et "
          "aucune requête ne peut descendre en dessous aujourd'hui. Voir le levier "
          "« Le plancher fixe par requête ».")
        W("")
    W("**Ce qui est LENT** — et ce sont les cas que la promesse « sur tous les champs » met en avant :")
    W("")
    for r in slow:
        W(f"- `{r['class_id']}` / {r['window']} — **{fmt_dur(r['wall_p50_ms'])}** "
          f"({r['label']}), servi par `{r.get('served_from') or 'scan'}`")
    W("")
    maxread = max((r.get("read_bytes_total") or 0) for r in eff)
    availmin = min((((r.get("pressure_before") or {}).get("mem_available_bytes") or 0)
                    for r in eff), default=0)
    dbref = cfgmeta[ref].get("db_bytes") or 0
    W("**Le disque n'a pas été sollicité — et c'est une limite, pas une bonne nouvelle.** Octets lus "
      f"au bloc, maximum sur toutes les cellules : **{fmt_mib(maxread)} Mio**. La base "
      f"({fmt_mib(dbref)} Mio) tient entièrement dans le cache de pages de la machine "
      f"({fmt_mib(availmin)} Mio de mémoire disponible au minimum pendant la mesure). Ces latences "
      "sont donc **bornées par le CPU, pas par le stockage**, et constituent un MEILLEUR CAS. À un "
      "volume où la base dépasse la RAM disponible, le stockage entre dans l'équation — et ce "
      "régime n'est pas mesuré ici.")
    W("")
    W("**Ce que ces mesures n'autorisent PAS à affirmer** :")
    W("")
    W(f"- rien au-delà de {fmt_n(_nev0(ref))} événements. La cible de 10 M n'a pas été atteinte par "
      "le vrai chemin d'ingest — non pas faute de l'avoir cherché, mais parce que le débit "
      "d'ingest s'effondre avec le volume déjà en base, ce que la section « D'où vient "
      "l'effondrement » ATTRIBUE désormais (et non plus suppose) : le coût CPU par événement monte, "
      "le daemon écrit de plus en plus d'octets par ligne, et le chemin d'écriture est séquentiel. "
      "Le coût restant pour atteindre 10 M y est chiffré, en tant que PLANCHER arithmétique sur des "
      "débits mesurés. Toute latence annoncée à 10 M ou 100 M serait une extrapolation, pas une "
      "mesure.")
    _cold_on = [c for c in configs
                if str(cfgmeta[c].get("cold", "off")).lower() not in ("off", "0", "", "none")]
    if _cold_on:
        # TOUTES les configurations froides sont nommées, pas seulement la première : depuis qu'une
        # passe corrigée coexiste avec la passe qui a mesuré le défaut, n'en citer qu'une ferait
        # croire qu'il n'y en a qu'une — et laisserait le lecteur sur la mauvaise.
        _cold_list = ", ".join(f"`{c}`" for c in _cold_on)
        # La concurrence n'est retirée de cette phrase QUE si elle a réellement été tirée : la
        # présence de lignes `concurrency` est le seul critère, jamais une affirmation d'auteur.
        _cc = ("le multi-tenant" if conc else "la concurrence ni le multi-tenant")
        W(f"- rien sur {_cc} (voir la section dédiée). Le tier froid, lui, "
          f"EST mesuré ici — mais seulement dans {_cold_list}, à une seule fenêtre chaude et un "
          "seul volume : les autres tableaux restent des tableaux SANS tier froid.")
    else:
        W("- rien sur le tier froid, "
          + ("le multi-tenant" if conc else "la concurrence, ni le multi-tenant")
          + " (voir la section dédiée).")
    if conc:
        _cn = max((r.get("analysts") or 0) for r in conc)
        W(f"- la CONCURRENCE, elle, est mesurée : jusqu'à {_cn} analystes simultanés lançant de très "
          "grosses requêtes sous le même budget de 2 Gio appliqué, avec vérification que la réponse "
          "concurrente est IDENTIQUE à la réponse obtenue seul (section dédiée).")
    # MÊME correctif que pour les leviers : ne pas exiger le volume EXACT, sinon l'axe masquage
    # disparaît du verdict dès qu'une nouvelle passe compte quelques événements de plus.
    mk = max([c for c in configs if "non-vide" in (cfgmeta[c].get("mask") or "")] or [None],
             key=lambda c: _nev0(c) if c else -1)
    worst = None
    if mk:
        for cid, _lab, _k in classes:
            for w in wins:
                x, y = idx.get((mk, cid, w)), idx.get((ref, cid, w))
                if x and y and x.get("wall_p50_ms") and y.get("wall_p50_ms"):
                    rr = x["wall_p50_ms"] / y["wall_p50_ms"]
                    if worst is None or rr > worst[0]:
                        worst = (rr, cid, w, y["wall_p50_ms"], x["wall_p50_ms"])
    best = None
    if mk:
        for cid, _lab, _k in classes:
            for w in wins:
                x, y = idx.get((mk, cid, w)), idx.get((ref, cid, w))
                if x and y and x.get("wall_p50_ms") and y.get("wall_p50_ms"):
                    rr = x["wall_p50_ms"] / y["wall_p50_ms"]
                    if best is None or rr < best[0]:
                        best = (rr, cid, w, y["wall_p50_ms"], x["wall_p50_ms"])
    if worst:
        W(f"- rien sur un déploiement AVEC masquage à partir des chiffres masque-vide : l'écart "
          f"mesuré le plus fort est **x{worst[0]:.1f}** sur `{worst[1]}` / {worst[2]} "
          f"({fmt_dur(worst[3])} masque vide contre {fmt_dur(worst[4])} masque non vide).")
        if best and best[0] < 0.9:
            rw = idx.get((mk, best[1], best[2])) or {}
            rv = idx.get((ref, best[1], best[2])) or {}
            same = rw.get("rows") == rv.get("rows")
            W(f"  Et le masquage ne va pas TOUJOURS dans le sens du ralentissement : sur "
              f"`{best[1]}` / {best[2]} il est **x{best[0]:.2f}**, donc plus RAPIDE "
              f"({fmt_dur(best[3])} masque vide contre {fmt_dur(best[4])} masque non vide, "
              f"{'même nombre de lignes rendues' if same else f'{fmt_n(rv.get(chr(114)+chr(111)+chr(119)+chr(115)))} lignes contre {fmt_n(rw.get(chr(114)+chr(111)+chr(119)+chr(115)))}'}). "
              "**La cause n'est PAS établie par cette mesure**, et on ne va pas l'inventer. Deux "
              "mécanismes candidats, qui demandent chacun une expérience dédiée pour être "
              "départagés : (a) un masque posé sur une dimension à haute cardinalité l'effondre, il "
              "reste moins de groupes à agréger — la requête va plus vite **parce que la réponse a "
              "changé** ; (b) la passe masquée a tourné APRÈS la passe non masquée, donc sur un "
              "cache de pages plus chaud. Ce qui trancherait : rejouer les deux passes dans l'ordre "
              "inverse, et comparer les résultats ligne à ligne. En attendant, la règle est simple — "
              "**une latence qui baisse en présence d'un masque ne doit jamais être citée comme un "
              "gain**.")
    else:
        W("- rien sur un déploiement AVEC masquage : cet axe n'a pas pu être comparé cellule par "
          "cellule dans cette passe.")
    W("")
    W("## Matériel et conditions")
    W("")
    W("| | |")
    W("|---|---|")
    W(f"| Processeur | {hw['cpu']} ({hw['cores']} cœurs logiques) |")
    W(f"| RAM de la machine | {hw['mem_total_bytes']/2**30:.1f} Gio |")
    W(f"| Noyau | {hw['kernel']} |")
    W(f"| Version de plume mesurée | `{cfgmeta[configs[-1]].get('version','inconnue')}` |")
    vols = sorted({cfgmeta[c].get("events") or 0 for c in configs})
    W(f"| Volumes mesurés | {', '.join(fmt_n(v) + ' événements' for v in vols)} |")
    W(f"| Taille de la base (SQLCipher, chiffrée) | {', '.join(sorted({fmt_mib(cfgmeta[c].get('db_bytes')) + ' Mio' for c in configs}))} |")
    W("| Budget mémoire | **appliqué** par un scope systemd `MemoryMax=2G MemorySwapMax=0` — "
      "la même contrainte que la limite de conteneur de production (`limits.memory: 2Gi`) |")
    W("| Concurrence de requêtes | `PLUME_QUERY_CONCURRENCY=3` (le défaut livré) |")
    if conc:
        _cs = sorted({r.get("query_sem") for r in conc if r.get("query_sem")})
        _cn = sorted({r.get("analysts") for r in conc if r.get("analysts")})
        W(f"| Passes de CONCURRENCE | {', '.join(str(n) for n in _cn)} analystes simultanés, "
          f"sémaphore {' et '.join(str(s) for s in _cs)} (section dédiée) |")
    W("| Budget par requête | interactif, 60 s (`interactive:true`) |")
    W("")
    _bins = sorted({(r.get("config") or {}).get("version", "").split(" ")[0]
                    for r in eff if (r.get("config") or {}).get("version")}
                   | {(d.get("version") or "").split(" ")[0]
                      for d in ingest if d.get("version")})
    if len(_bins) > 1:
        W("**Plusieurs binaires** figurent dans ce document : " + ", ".join(f"`{b}`" for b in _bins)
          + ". Chaque cellule porte le sien dans le JSONL brut, et chaque tableau de configuration "
          "l'affiche dans son sous-titre. Une comparaison entre deux tableaux de binaires "
          "différents mesure aussi l'écart entre les deux binaires — ce n'est légitime que dans la "
          "section « Écart mesuré entre deux passes », qui le dit.")
        W("")
    W("**Honnêteté sur les conditions** : la machine de mesure n'était pas dédiée — d'autres travaux")
    W("tournaient en parallèle. Chaque cellule enregistre son `loadavg` et le swap consommé pendant")
    W("la mesure ; les cellules prises sous swap sont marquées et listées plus bas. Le daemon lui-même")
    W("ne pouvait pas swapper (`MemorySwapMax=0`), donc sa RSS crête est une vraie crête, mais les")
    W("latences absolues sont **pessimistes** sur une machine chargée.")
    W("")

    # Si la phase d'ingest n'a pas écrit sa ligne de synthèse (remplissage interrompu à un volume
    # borné, par exemple), on la RECONSTRUIT depuis l'échantillonneur — qui est de la donnée mesurée,
    # pas une estimation — et on le DIT dans le tableau.
    curve_sets = []
    for _c0 in (args.ingest_curve or []):
        import csv as _csv0
        try:
            curve_sets.append(list(_csv0.DictReader(open(_c0, encoding="utf-8"))))
        except OSError:
            pass
    # On AJOUTE la ligne dérivée de l'échantillonneur dès qu'il y a une courbe : sans ça, une passe
    # dont la synthèse n'a pas été écrite (remplissage borné en temps) disparaîtrait du tableau au
    # profit d'une autre passe qui, elle, avait écrit la sienne.
    for curve_pts in curve_sets:
        if len(curve_pts) < 2:
            continue
        f0, f1 = curve_pts[0], curve_pts[-1]
        dt = int(f1["t_unix"]) - int(f0["t_unix"])
        dn = int(f1["events"]) - int(f0["events"])
        if dt > 0:
            ingest.append({"events": dn, "seconds": dt, "events_per_second": dn // dt,
                           "db_bytes": int(f1["db_bytes"]), "fts_fields": 0,
                           "path": "POST /api/ingest -> spool -> ingest_events_batch",
                           "_derived": "reconstruit depuis l'échantillonneur (premier et dernier "
                                       "point mesurés), le remplissage ayant été borné en temps"})
    if [x for x in ingest if x.get("phase") in (None, "ingest")]:
        W("## Débit d'ingest mesuré (chemin HTTP complet)")
        W("")
        # La colonne « binaire » n'est pas décorative : les passes d'INGEST et les passes de
        # REQUÊTE de ce document n'ont pas toutes été tirées avec le même binaire. Le taire
        # laisserait croire à une passe unique.
        W("| Événements | Durée | Débit | Base après | `PLUME_FTS_FIELDS` | Binaire |")
        W("|---:|---:|---:|---:|:--:|---|")
        for d in [x for x in ingest if x.get("phase") in (None, "ingest")]:
            _v = (d.get("version") or "").split(" ")[0] or "—"
            W(f"| {fmt_n(d.get('events'))} | {d.get('seconds')} s | "
              f"**{fmt_n(d.get('events_per_second'))} ev/s** | {fmt_mib(d.get('db_bytes'))} Mio | "
              f"{d.get('fts_fields')} | `{_v}` |")
        W("")
        W("Chemin traversé : `" + next(x.get('path','') for x in ingest
                                       if x.get('phase') in (None, 'ingest')) + "`.")
        W("")
        for d in ingest:
            if d.get("_derived"):
                W(f"> Ligne de {fmt_n(d.get('events'))} événements : **{d['_derived']}.**")
                W("")
        if args.fill_log:
            # Le générateur est RÉGULÉ sur la profondeur du spool : son débit de production EST
            # donc le débit d'ingest de bout en bout. Ses lignes de progression couvrent le DÉBUT du
            # remplissage, que l'échantillonneur (démarré plus tard) peut manquer.
            import re as _re
            pat = _re.compile(r"^\s*(\d+) événements\s+([\d.]+) Mio\s+(\d+) ev/s produits")
            fpts = []
            try:
                for line in open(args.fill_log, encoding="utf-8", errors="replace"):
                    m = pat.match(line)
                    if m:
                        fpts.append((int(m.group(1)), float(m.group(2)), int(m.group(3))))
            except OSError:
                fpts = []
            if fpts:
                W("Débit **cumulé** relevé par le générateur lui-même pendant le remplissage (il est "
                  "régulé sur la profondeur du spool : son débit de production est donc le débit "
                  "d'ingest de bout en bout). Ces points couvrent le DÉBUT du remplissage :")
                W("")
                W("| Événements produits | Volume produit | Débit cumulé mesuré |")
                W("|---:|---:|---:|")
                for n, mio, rate in fpts:
                    W(f"| {fmt_n(n)} | {mio:.0f} Mio | **{fmt_n(rate)} ev/s** |")
                W("")
                if len(fpts) >= 2:
                    W(f"Le débit cumulé passe de **{fmt_n(fpts[0][2])} ev/s** à "
                      f"**{fmt_n(fpts[-1][2])} ev/s** entre {fmt_n(fpts[0][0])} et "
                      f"{fmt_n(fpts[-1][0])} événements produits, soit **x{fpts[0][2]/max(fpts[-1][2],1):.1f}**. "
                      "Deux causes se superposent — le volume déjà en base (maintenance des index et "
                      "de la FTS5) et la charge de la machine — et cette passe ne les sépare pas. "
                      "C'est pour ça que la cible de 10 M n'a pas été atteinte : à ce débit, il "
                      "aurait fallu plusieurs heures de plus.")
                    W("")
        for _ci, _curve in enumerate(args.ingest_curve or []):
            # UNE SOUS-SECTION PAR COURBE. Deux remplissages du MÊME volume, l'un sur machine
            # chargée et l'autre sur machine au repos, se lisent côte à côte : c'est ce qui
            # SÉPARE la contention du volume, au lieu de les mélanger dans une seule phrase.
            import os as _o2
            W(f"### Courbe de remplissage — `{_o2.path.basename(_curve)}`")
            W("")
            import csv as _csv
            try:
                pts = list(_csv.DictReader(open(_curve, encoding="utf-8")))
            except OSError:
                pts = []
            segs = []
            for x, y in zip(pts, pts[1:]):
                dt = int(y["t_unix"]) - int(x["t_unix"])
                dn = int(y["events"]) - int(x["events"])
                if dt > 0 and dn >= 0:
                    segs.append((int(y["events"]), int(y["db_bytes"]), int(y["rss_bytes"]),
                                 dn / dt, float(y["loadavg1"])))
            if segs:
                W("#### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé")
                W("")
                W("Un débit moyen seul cacherait cette dégradation. Chaque ligne est un intervalle")
                W("d'échantillonnage réel pendant le remplissage (la maintenance des index et de la")
                W("FTS coûte de plus en plus cher à mesure que les b-trees grossissent).")
                W("")
                W("| Lignes en base | Taille base | RSS du daemon | Débit sur l'intervalle | `loadavg` |")
                W("|---:|---:|---:|---:|---:|")
                step = max(1, len(segs) // 12)
                for n, db, rss, rate, la in segs[::step]:
                    W(f"| {fmt_n(n)} | {fmt_mib(db)} Mio | {fmt_mib(rss)} Mio | "
                      f"{fmt_n(int(rate))} ev/s | {la:.1f} |")
                W("")
                # ------------------------------------------------ ATTRIBUTION (colonnes riches)
                iv = [d for d in ingest_intervals(_curve) if d.get("cpu_ms_per_event")]
                if len(iv) >= 4:
                    W("##### D'où vient l'effondrement — attribution mesurée, pas supposée")
                    W("")
                    W("Un débit qui tombe ne dit pas POURQUOI il tombe. Trois grandeurs le disent, et")
                    W("elles sont relevées à chaque tick par `bench/probe.py` :")
                    W("")
                    W("- **CPU du daemon par événement** — s'il monte, le travail par ligne grandit")
                    W("  vraiment (b-trees plus profonds, index et FTS à maintenir) : c'est le VOLUME.")
                    W("- **CPU consommé par le reste de la machine** — c'est la CONTENTION. Elle inclut")
                    W("  les fils noyau qui exécutent NOS propres écritures : ce n'est donc pas")
                    W("  seulement « d'autres travaux », c'est « du CPU non facturé au daemon ».")
                    W("- **Octets lus au bloc et stall mémoire du cgroup** — si le plafond de 2 Gio")
                    W("  forçait la récupération du cache de pages, ils monteraient. Le budget est")
                    W("  appliqué par ce même cgroup, et son cache de pages lui est facturé.")
                    W("")
                    W("| Lignes en base | Débit | CPU daemon / événement | cœurs daemon | cœurs du reste | lu au bloc | écrit / 1 000 év. | stall mémoire | part de la sonde |")
                    W("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
                    stp = max(1, len(iv) // 12)
                    for d in iv[::stp]:
                        W(f"| {fmt_n(d['events'])} | {fmt_n(int(d['rate']))} ev/s | "
                          f"{d['cpu_ms_per_event']:.3f} ms | {d.get('daemon_cores') or 0:.2f} | "
                          f"{d.get('other_cores') if d.get('other_cores') is not None else float('nan'):.2f} | "
                          f"{fmt_mib(d.get('d_read_bytes') or 0)} Mio | "
                          f"{(d.get('d_write_bytes') or 0)/max(d['dn'],1)*1000/2**20:.1f} Mio | "
                          f"{(d.get('d_cg_mem_stall_us') or 0)/1000:.0f} ms | "
                          f"{100*(d.get('count_ms') or 0)/1000/max(d['dt'],1):.1f} % |")
                    W("")
                    # L'INSTRUMENT SE COMPTE LUI-MÊME. Le comptage des lignes qui sert d'abscisse est
                    # un scan : à gros volume il consomme une part croissante de l'intervalle, ET son
                    # CPU est facturé au daemon. Sans cette colonne, sa dépense se lirait comme une
                    # dégradation du produit.
                    pr = [(d.get("count_ms") or 0) / 1000 / max(d["dt"], 1) for d in iv]
                    _prs = sorted(pr)
                    W(f"« Part de la sonde » = ce que le COMPTAGE DES LIGNES de l'échantillonneur "
                      f"consomme de l'intervalle : **{100*_prs[len(_prs)//2]:.1f} % en médiane**, "
                      f"**{100*_prs[-1]:.1f} % au pire**. Ce comptage est un scan servi par le daemon : "
                      "son coût est DANS les colonnes CPU et débit ci-dessus. La dégradation nette du "
                      "produit est donc un peu plus faible que celle affichée — jamais plus forte.")
                    W("")
                    k = max(1, len(iv) // 4)
                    cpu0 = sum(d["cpu_ms_per_event"] for d in iv[:k]) / k
                    cpu1 = sum(d["cpu_ms_per_event"] for d in iv[-k:]) / k
                    r0 = sum(d["rate"] for d in iv[:k]) / k
                    r1 = sum(d["rate"] for d in iv[-k:]) / k
                    n0, n1 = iv[:k][0]["events"], iv[-1]["events"]
                    oth = sorted(d["other_cores"] for d in iv if d.get("other_cores") is not None)
                    othmed = oth[len(oth) // 2] if oth else None
                    dmn = sorted(d["daemon_cores"] for d in iv if d.get("daemon_cores") is not None)
                    dmnmed = dmn[len(dmn) // 2] if dmn else None
                    rd = sum(d.get("d_read_bytes") or 0 for d in iv)
                    stall = sum(d.get("d_cg_mem_stall_us") or 0 for d in iv) / 1e6
                    # Le VERDICT est CALCULÉ, jamais rédigé d'avance : chaque facteur est le rapport
                    # de deux colonnes mesurées, et la phrase choisie dépend de ce que ces rapports
                    # valent. Une passe où le débit ne tomberait pas produirait une autre phrase.
                    fall = r0 / max(r1, 1e-9)
                    cpu_growth = cpu1 / max(cpu0, 1e-9)
                    W(f"Entre {fmt_n(n0)} et {fmt_n(n1)} lignes en base, le débit passe de "
                      f"**{fmt_n(int(r0))} à {fmt_n(int(r1))} ev/s** (**÷{fall:.2f}**) et le coût CPU "
                      f"du daemon par événement de **{cpu0:.3f} à {cpu1:.3f} ms** "
                      f"(**×{cpu_growth:.2f}**).")
                    W("")
                    # DÉCOMPOSITION EXACTE, pas une part estimée : le débit EST le quotient des deux
                    # colonnes mesurées, `débit = cœurs occupés par le daemon / CPU par événement`.
                    # La chute se factorise donc SANS reste entre « le travail par ligne a grandi » et
                    # « le daemon tourne moins souvent » (il attend). Les deux facteurs sont mesurés.
                    c0 = sum(d.get("daemon_cores") or 0 for d in iv[:k]) / k
                    c1 = sum(d.get("daemon_cores") or 0 for d in iv[-k:]) / k
                    if cpu_growth >= 1.15 and fall >= 1.15:
                        W(f"Cette chute se FACTORISE, sans reste, en deux facteurs mesurés — le débit "
                          f"est exactement `cœurs occupés / CPU par événement` :")
                        W("")
                        _prod = cpu_growth * (c0 / max(c1, 1e-9))
                        W(f"> **÷{fall:.2f}** (débit mesuré) = **×{cpu_growth:.2f}** (CPU par "
                          f"événement : le travail par ligne grandit avec les b-trees) × "
                          f"**÷{c0/max(c1,1e-9):.2f}** (cœurs occupés par le daemon : {c0:.2f} au "
                          f"début contre {c1:.2f} à la fin — il ATTEND davantage). Le produit vaut "
                          f"÷{_prod:.2f}, soit {abs(_prod-fall)/fall*100:.0f} % d'écart avec la chute "
                          "mesurée : l'écart est celui de la moyenne par quartile, l'identité "
                          "`débit = cœurs / CPU par événement` étant exacte intervalle par intervalle.")
                        W("")
                        W(f"Le travail par ligne grandit donc RÉELLEMENT avec le volume déjà en base : "
                          f"c'est le VOLUME, pas la machine. Et le daemon n'occupe jamais plus de "
                          f"{max((d.get('daemon_cores') or 0) for d in iv):.2f} cœur sur les 12 "
                          "disponibles : le chemin d'écriture est SÉQUENTIEL, ajouter des cœurs n'y "
                          "changerait rien.")
                    elif cpu_growth < 1.15 and fall >= 1.15:
                        W("Le coût CPU par événement ne bouge PAS pendant que le débit tombe : le "
                          "daemon n'a pas plus de travail par ligne, il ATTEND. La cause n'est donc "
                          "pas le volume en base.")
                    else:
                        W("Le débit ne s'effondre pas sur cet intervalle : il n'y a rien à attribuer.")
                    W("")
                    if dmnmed is not None and othmed is not None:
                        W(f"Le daemon occupe **{dmnmed:.2f} cœur** en médiane pendant que le reste de "
                          f"la machine en occupe **{othmed:.2f}** (12 cœurs disponibles). "
                          + ("La machine n'est donc pas saturée : la chute n'est pas une contention "
                             "de CPU disponible." if dmnmed + othmed < 8 else
                             "La machine est proche de la saturation : une part de la chute est de "
                             "la contention."))
                        W("")
                    # CE QUE ÇA COÛTE D'ALLER PLUS HAUT. Arithmétique sur des débits MESURÉS, et
                    # présentée comme un PLANCHER : le débit baisse encore au-delà, donc le vrai
                    # coût est SUPÉRIEUR. Ce n'est pas une mesure à 10 M, et c'est écrit.
                    for target in (10_000_000,):
                        if n1 < target:
                            h = (target - n1) / max(r1, 1) / 3600.0
                            W(f"**Ce que coûterait {fmt_n(target)} événements** : au DERNIER débit "
                              f"mesuré ({fmt_n(int(r1))} ev/s), il resterait {fmt_n(target - n1)} "
                              f"événements à ingérer, soit **{h:.1f} h** — et c'est un PLANCHER, "
                              f"puisque le débit a déjà été divisé par {fall:.1f} sur la plage "
                              "mesurée et continue de baisser. Cette ligne est de l'arithmétique sur "
                              "des débits mesurés, PAS une mesure à ce volume : aucune latence de ce "
                              "document ne vaut au-delà du volume réellement rempli.")
                            W("")
                    W(f"**Le stockage n'est pas en cause côté LECTURE** : {fmt_mib(rd)} Mio lus au bloc "
                      f"sur tout le remplissage — la base tient dans le cache de pages. **Le plafond de "
                      f"2 Gio ne freine pas non plus par récupération mémoire** : {stall:.1f} s de stall "
                      "mémoire cumulé sur le cgroup, mesuré.")
                    W("")
                rates = sorted(r for _, _, _, r, _ in segs)
                las = sorted(la for _, _, _, _, la in segs)
                med = rates[len(rates) // 2]
                base = (f"Débit sur les intervalles échantillonnés : **min {rates[0]:.0f} ev/s, "
                        f"médiane {med:.0f} ev/s, max {rates[-1]:.0f} ev/s**, pour un `loadavg` "
                        f"allant de {las[0]:.1f} à {las[-1]:.1f}. L'écart d'un facteur "
                        f"{rates[-1]/max(rates[0],1):.1f} entre le plus lent et le plus rapide "
                        "intervalle ")
                if len(iv) >= 4:
                    # La sonde a relevé le CPU : la cause est ATTRIBUÉE au-dessus, on ne la devine
                    # plus depuis le `loadavg` (qui compte aussi les tâches en attente d'E/S et ne
                    # dit à qui appartient aucune d'elles).
                    W(base + "n'est plus interprété depuis le `loadavg` : la sous-section "
                             "d'attribution ci-dessus le décompose en CPU du daemon, CPU du reste de "
                             "la machine et attente du stockage — trois grandeurs mesurées.")
                else:
                    W(base + "suit le `loadavg` : **cette passe ne sépare pas** le volume déjà en "
                             "base de la charge de la machine — son CSV est antérieur à la sonde qui "
                             "relève le CPU par processus. À lire comme un PLANCHER.")
                W("")
                W("La colonne RSS est la mémoire réellement occupée par le daemon PENDANT l'ingest — "
                  f"crête échantillonnée ici : **{fmt_mib(max(x[2] for x in segs))} Mio**, à "
                  "confronter au budget de 2 Gio. C'est une mesure, pas une estimation.")
                W("")
                W("> Portée de cette courbe : l'échantillonneur ne couvre que la fenêtre où il a "
                  f"tourné ({fmt_n(segs[0][0])} à {fmt_n(segs[-1][0])} lignes). Ce qui s'est passé "
                  "avant n'est pas dans ce tableau, et n'est donc pas mesuré ici.")
                W("")

    W("## Configurations mesurées")
    W("")
    W("| Étiquette | Événements | Hôtes | `PLUME_FTS_FIELDS` | Masquage de champs | Tier froid | Classes mesurées |")
    W("|---|---:|---:|:--:|---|:--:|---|")
    for c in configs:
        m = cfgmeta[c]
        n_cells = sum(1 for r in eff if r["config_id"] == c)
        sub = m.get("classes")
        # La colonne « Hôtes » est la cardinalité de `host` DU JEU DE DONNÉES, pas un réglage : elle
        # vient du profil lu par le générateur. Sans elle, deux passes au même volume mais à des
        # cardinalités d'hôte différentes seraient indiscernables dans ce tableau.
        W(f"| `{c}` | {fmt_n(m.get('events'))} | {m.get('hosts', '?')} | {m.get('fts_fields','?')} | "
          f"{m.get('mask','?')} | {m.get('cold','?')} | "
          f"{'toutes' if not sub else '**sous-ensemble** `' + sub + '`'} ({n_cells} cellules) |")
    W("")
    W("Le masquage compte parce qu'il est **contre-intuitif** : un ensemble de masquage non vide")
    W("désarme la route de rollups *et* le moteur vectorisé (`handlers/query.rs:282`,")
    W("`cold_store/planner.rs:601`). Le rempart de confidentialité est un frein de performance, donc")
    W("des chiffres publiés sans cet axe ne vaudraient que pour un déploiement **sans** masquage.")
    W("Toutes les cellules sont tirées avec le **même rôle** (`viewer`) dans les deux états : une règle")
    W("de masque à `role:''` ne contraint pas un admin (`field_filter.rs:110-115`), le comparer en")
    W("admin ne mesurerait rien.")
    W("")

    # ---------------------------------------------------------------- tableaux
    for c in configs:
        m = cfgmeta[c]
        W(f"## Résultats — `{c}`")
        W("")
        W(f"*`PLUME_FTS_FIELDS`={m.get('fts_fields')}, masquage={m.get('mask')}, "
          f"froid={m.get('cold')}, version=`{m.get('version')}`, "
          f"{fmt_n(m.get('events'))} événements, base {fmt_mib(m.get('db_bytes'))} Mio.*")
        W("")
        reps_seen = sorted({r.get("reps") for r in eff if r["config_id"] == c and r.get("reps")})
        W("Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du")
        W("processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le")
        W("processus (0 = servi depuis le cache de pages).")
        W("")
        disp = [r for r in eff if r["config_id"] == c and r.get("wall_p50_ms")
                and r.get("wall_p95_ms") and r["wall_p95_ms"] / r["wall_p50_ms"] > 3]
        if disp:
            W("")
            W(f"**{len(disp)} cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** "
              "Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la "
              "mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur "
              "`p50` reste utilisable, leur `p95` non.")
        W("")
        W(f"**Ce que `p95` vaut ici** : {', '.join(str(x) for x in reps_seen)} répétitions par "
          "cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice "
          "tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum "
          "observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de "
          "distribution. Le lire comme « le pire des N tirs », rien de plus.")
        W("")
        if m.get("classes"):
            W(f"> Cette configuration ne mesure que les classes `{m['classes']}`. Les classes absentes")
            W("> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas")
            W("> implicitement inchangées.")
            W("")
        W("| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |")
        W("|---|:--:|---:|---:|---:|---:|---:|---:|---|---|")
        for cid, label, kind in classes:
            for w in wins:
                r = idx.get((c, cid, w))
                if not r:
                    continue
                notes = []
                if r.get("errors"):
                    notes.append("ERREUR: " + "; ".join(x[:70] for x in r["errors"]))
                if r.get("truncated"):
                    notes.append("tronqué")
                if r.get("approx"):
                    notes.append("approx")
                if r.get("swap_suspect"):
                    notes.append("**pris sous swap — à rejouer**")
                if (r.get("peak_rss_bytes") or 0) > BUDGET_BYTES:
                    notes.append("**> 2 Gio**")
                if r.get("reps_ok", 0) < r.get("reps", 0):
                    notes.append(f"{r['reps_ok']}/{r['reps']} tirs OK")
                # Dispersion p95/p50 : sur une machine partagée, un facteur >3 entre le pire et le
                # médian ne dit rien de plume, il dit que la mesure a été bousculée. On le MARQUE
                # au lieu de publier un p95 comme s'il décrivait le produit.
                p50v, p95v = r.get("wall_p50_ms"), r.get("wall_p95_ms")
                if p50v and p95v and p50v > 0 and p95v / p50v > 3:
                    la = (r.get("pressure_before") or {}).get("loadavg") or [0]
                    notes.append(f"dispersion x{p95v/p50v:.1f} (loadavg {la[0]:.0f}) — "
                                 "p95 dominé par la contention, pas par plume")
                W(f"| `{cid}` <br><sub>{label}</sub> | {w} | "
                  f"{fmt_ms(r.get('wall_p50_ms'))} | {fmt_ms(r.get('wall_p95_ms'))} | "
                  f"{fmt_ms(r.get('cold_first_wall_ms'))} | "
                  f"{fmt_mib(r.get('peak_rss_bytes'))} | {fmt_mib(r.get('read_bytes_first'))} | "
                  f"{fmt_n(r.get('rows'))} | {r.get('served_from') or 'scan'} | "
                  f"{' / '.join(notes) if notes else ''} |")
        W("")

    # ---------------------------------------------------------------- verdicts
    # ------------------------------------------------------------ ÉCART AVANT/APRÈS (option)
    # Un correctif ne se publie pas en réécrivant les tableaux : on mesure DEUX FOIS, avec le même
    # instrument et la même base, et on montre l'écart cellule par cellule. Une cellule absente d'un
    # côté reste absente (jamais complétée par déduction).
    for _i, _pair in enumerate(args.compare or []):
        try:
            c_av, c_ap = _pair.split(":", 1)
        except ValueError:
            raise SystemExit("--compare attend AVANT:APRES")
        missing = [c for c in (c_av, c_ap) if c not in configs]
        if missing:
            raise SystemExit("--compare : configuration(s) absente(s) des résultats : " + ", ".join(missing))
        _note = (args.compare_note or [])[_i] if _i < len(args.compare_note or []) else None
        W(f"## Écart mesuré entre deux passes — `{c_av}` vs `{c_ap}`")
        W("")
        W(f"Comparaison `{c_av}` -> `{c_ap}`, MÊME base, MÊME instrument, MÊME machine, passes "
          "consécutives. Les deux lignes sont des mesures ; le delta est leur soustraction, rien de plus.")
        W("")
        if _note:
            W(f"**Ce qui a changé entre les deux passes** : {_note}")
            W("")
        W(f"Charge machine relevée : `loadavg` {_cmp_load(eff, c_av)} pendant la passe AVANT, "
          f"{_cmp_load(eff, c_ap)} pendant la passe APRÈS. Sur une machine partagée, un écart de "
          "quelques millisecondes ne prouve rien ; seuls les écarts francs sont exploitables, et les "
          "cellules dont la dispersion est annotée plus haut restent à lire avec la même réserve.")
        W("")
        W("| Classe | Fenêtre | p50 avant | p50 après | delta | SQL avant | SQL après | route avant | route après |")
        W("|---|:--:|---:|---:|---:|---:|---:|---|---|")
        seen_pairs = 0
        for cid, win in [(r["class_id"], r["window"]) for r in eff if r["config_id"] == c_ap]:
            a, b = idx.get((c_av, cid, win)), idx.get((c_ap, cid, win))
            if not a or not b or a.get("wall_p50_ms") is None or b.get("wall_p50_ms") is None:
                continue
            seen_pairs += 1
            d = b["wall_p50_ms"] - a["wall_p50_ms"]
            sign = "+" if d > 0 else ""
            # Un delta entre deux réponses DIFFÉRENTES n'est pas un gain. Quand un côté tronque, la
            # cellule le porte : sans ce marqueur, un « -5 s » se lirait comme une accélération alors
            # qu'il mesure une réponse incomplète.
            trunc = " ⚠ **réponse tronquée d'un côté**" if (a.get("truncated") or b.get("truncated")) else ""
            W(f"| `{cid}` | {win} | {fmt_dur(a['wall_p50_ms'])} | {fmt_dur(b['wall_p50_ms'])} | "
              f"{sign}{fmt_dur(d)}{trunc} | {fmt_dur(a.get('sql_p50_ms'))} | {fmt_dur(b.get('sql_p50_ms'))} | "
              f"{a.get('served_from') or '—'} | {b.get('served_from') or '—'} |")
        W("")
        only_ap = sorted({(r["class_id"], r["window"]) for r in eff if r["config_id"] == c_ap}
                         - {(r["class_id"], r["window"]) for r in eff if r["config_id"] == c_av})
        only_av = sorted({(r["class_id"], r["window"]) for r in eff if r["config_id"] == c_av}
                         - {(r["class_id"], r["window"]) for r in eff if r["config_id"] == c_ap})
        _nt = sum(1 for cid, win in [(r["class_id"], r["window"]) for r in eff if r["config_id"] == c_ap]
                  if (idx.get((c_av, cid, win)) or {}).get("truncated")
                  or (idx.get((c_ap, cid, win)) or {}).get("truncated"))
        if _nt:
            W(f"**{_nt} de ces lignes opposent des réponses de contenu DIFFÉRENT** (un côté tronque) : "
              "leur delta mesure un écart de travail, pas un écart de vitesse. Elles sont marquées.")
            W("")
        W(f"{seen_pairs} cellules comparables. "
          + (f"Mesurées SEULEMENT après : {', '.join(f'`{c}`/{w}' for c, w in only_ap)}. " if only_ap else "")
          + (f"Mesurées SEULEMENT avant : {', '.join(f'`{c}`/{w}' for c, w in only_av)}. " if only_av else "")
          + "Une cellule non comparable n'est PAS un résultat neutre : elle est absente d'un côté.")
        W("")

    # ------------------------------------------------------------ FENÊTRES (dont les non mesurées)
    W("## Les fenêtres mesurées, et celles qui ne le sont pas")
    W("")
    W("Les fenêtres ne sont pas choisies : elles sont DÉRIVÉES de deux paramètres du produit — la")
    W("fenêtre chaude (`PLUME_COLD_HOT_WINDOW_DAYS`, défaut **7 j**, `cold_store/aging.rs`) et la")
    W("rétention (`PLUME_RETENTION_DAYS`) — puis filtrées par l'étendue réelle du jeu de données.")
    W("")
    W("| Fenêtre | Ce qu'elle mesure |")
    W("|---|---|")
    _wl = {}
    for r in rows:
        if r.get("window_label"):
            _wl[r["window"]] = r["window_label"]
    for w in wins:
        W(f"| `{w}` | {_wl.get(w, '—')} |")
    W("")
    if unmeasured_win:
        _seen_w = {}
        for d in unmeasured_win:
            _seen_w[d["window"]] = d
        W("**Fenêtres écartées par la garde de couverture — donc NON MESURÉES** :")
        W("")
        for w, d in sorted(_seen_w.items()):
            W(f"- `{w}` ({d.get('label')}) — {d.get('why')}")
        W("")
        W("Une fenêtre plus large que le jeu ne mesure pas ce que dit son étiquette : elle mesure")
        W("`tout` sous un autre nom. Le harnais refuse de la tirer plutôt que de publier une cellule")
        W("dont le titre serait faux. Pour l'obtenir, il faut un jeu qui la couvre — c'est-à-dire")
        W("remplir sur une étendue plus longue (`BENCH_SPAN_DAYS`), pas rendre la garde plus permissive.")
        W("")

    # ------------------------------------------------------------ TIER FROID
    cold_cfgs = [c for c in configs
                 if str(cfgmeta[c].get("cold", "off")).lower() not in ("off", "0", "", "none")]
    cold_age = [d for d in ingest if d.get("phase") == "cold_age"]
    if cold_cfgs or cold_age:
        W("## Le tier froid — mesuré")
        W("")
        W("Avec une fenêtre chaude de 7 jours et une rétention de 365, `daemon/src/cold_store/` est")
        W("le chemin de lecture de **358 des 365 jours** d'une production. Les tableaux ci-dessus")
        W("tournent tous à `PLUME_COLD_TIER=0` : ils ne disent rien de ce chemin. Cette section est")
        W("la seule qui en parle, et elle ne parle que de ce qui a été tiré.")
        W("")
        for d in cold_age:
            moved = (d.get("hot_rows_before") or 0) - (d.get("hot_rows_after") or 0)
            hb, ha = d.get("hot_bytes_before") or 0, d.get("hot_bytes_after") or 0
            W("**Columnarisation mesurée** (chemin réel : `plume-daemon retention` -> `retention_run`")
            W(f"-> `cold_age_run`, fenêtre chaude {d.get('hot_window_days')} j) :")
            W("")
            W("| | Avant | Après |")
            W("|---|---:|---:|")
            W(f"| Lignes CHAUDES (SQLite) | {fmt_n(d.get('hot_rows_before'))} | {fmt_n(d.get('hot_rows_after'))} |")
            W(f"| Base chaude | {fmt_mib(hb)} Mio | {fmt_mib(ha)} Mio |")
            W(f"| Tier froid (Parquet chiffré) | 0 Mio | {fmt_mib(d.get('cold_bytes'))} Mio en {d.get('cold_files')} fichiers |")
            W("")
            pct = 100.0 * moved / max(d.get("hot_rows_before") or 1, 1)
            ratio = (d.get("cold_bytes") or 0) / max(moved, 1)
            W(f"**{fmt_n(moved)} lignes ({pct:.1f} %) ont quitté SQLite pour le Parquet**, en "
              f"{fmt_n(d.get('cold_files'))} fichiers (un par jour). Le froid pèse "
              f"**{ratio:.0f} octets par événement** là où le chaud en occupait "
              f"{(hb)/max(d.get('hot_rows_before') or 1,1):.0f} (table, index et FTS compris), "
              f"soit **{((hb)/max(d.get('hot_rows_before') or 1,1))/max(ratio,1):.0f}x plus "
              "compact**.")
            W("")
            # La DURÉE n'est publiée que si la passe qui l'a produite était propre. Une passe
            # interrompue puis reprise mesure l'interruption autant que le produit : on publie la
            # note, pas un débit qui aurait l'air d'en être un.
            if d.get("_note_seconds"):
                W(f"> Durée : {d['_note_seconds']}")
            elif d.get("seconds"):
                W(f"Durée mesurée : **{d['seconds']} s**, soit "
                  f"{moved/max(d.get('seconds') or 1,1):.0f} lignes/s.")
            W("")
            if ha > hb:
                W("> La base chaude n'a pas RÉTRÉCI : SQLite ne rend pas les pages au système, il les")
                W("> met en liste libre (`auto_vacuum=0`, comme en production). L'espace est réutilisé")
                W("> par les écritures suivantes, il n'est pas rendu au disque. C'est mesuré, pas supposé.")
                W("")
        for d in [x for x in ingest if str(x.get("phase") or "").startswith("cold_parity")]:
            W("### La réponse est-elle la MÊME ? (parité mesurée)")
            W("")
            W("Une latence n'est comparable que si les deux chemins rendent la même réponse : un")
            W("chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne")
            W("compare donc pas des temps, elle compare **les valeurs rendues**.")
            W("")
            W(f"Méthode : {d.get('method')}")
            W("")
            checks = d.get("checks") or []
            # DEUX SCHÉMAS COEXISTENT, et c'est délibéré. Les passes anciennes portent des contrôles
            # écrits À LA MAIN (`hot_value`/`cold_value`/`ratio`) ; les passes produites par
            # `bench/parity.py` portent un VERDICT par contrôle sur toute la matrice. On rend chacun
            # sous sa forme : réécrire l'ancien dans le nouveau serait inventer des chiffres.
            if checks and "verdict" in checks[0]:
                counts = d.get("counts") or {}
                W("| Verdict | n | ce qu'il signifie |")
                W("|---|---:|---|")
                W(f"| `same` | {counts.get('same', 0)} | les deux côtés rendent la MÊME réponse. |")
                W(f"| `differs` | {counts.get('differs', 0)} | ils divergent **sans le dire** — un nombre faux, "
                  "lisible et copiable. C'est LE cas grave. |")
                W(f"| `declared` | {counts.get('declared', 0)} | ils divergent et le côté froid le DIT (`truncated`, "
                  "ou note de couverture). L'incomplétude devient une information. |")
                W(f"| `refused` | {counts.get('refused', 0)} | un côté REFUSE, avec un motif nommé. Une erreur vaut "
                  "mieux qu'un nombre faux : c'est la position de repli, pas l'échec. |")
                W("")
                W("`declared` n'acquitte rien : un AGRÉGAT tronqué reste un nombre faux, déclaré ou non.")
                W("Les catégories ne s'additionnent jamais en un « tout va bien ».")
                W("")
                if "nombre_faux" in (d.get("counts") or {}):
                    nf = d["counts"]["nombre_faux"]
                    W(f"**Le compte qui compte : {nf} NOMBRE(S) FAUX.** C'est le nombre de contrôles dont la")
                    W("réponse porte une valeur calculée SUR L'ENSEMBLE (`count`/`dc`/`stats … by …`) et dont")
                    W("les deux côtés DIVERGENT — que le côté froid l'ait déclaré ou non. C'est exactement ce")
                    W("que l'invariant de `cold_store/exactness.rs` interdit. Les autres catégories décrivent")
                    W("des réponses partielles de LIGNES (vraies, incomplètes, signalées) ou des refus motivés :")
                    W("elles ne sont pas du même ordre de gravité.")
                    W("")
                if d.get("_reclassement"):
                    W(f"> Comptage : {d['_reclassement']}")
                    W("")
                notsame = [c for c in checks if c.get("verdict") != "same"]
                if notsame:
                    W("Le détail de tout ce qui n'est pas `same` :")
                    W("")
                    W("| Requête | Fenêtre | Verdict | Sans tier froid | Avec tier froid |")
                    W("|---|:--:|:--:|---|---|")
                    for ck in notsame:
                        _q = str(ck.get("query") or "").replace("|", "\\|")

                        def _side(x):
                            if x.get("values"):
                                return "**" + ", ".join(fmt_n(r[-1]) if isinstance(r, list) and r and isinstance(r[-1], int)
                                                        else str(r) for r in x["values"])[:60] + "**"
                            if x.get("status", 200) >= 400:
                                return f"refus {x.get('status')}"
                            n = x.get("rows")
                            tag = " (tronqué)" if x.get("truncated") else (" (couverture déclarée)" if x.get("coverage") else "")
                            return f"{fmt_n(n)} lignes `{x.get('digest')}`{tag}"

                        W(f"| `{_q}` | {ck['window']} | {ck['verdict']} | {_side(ck.get('hot') or {})} | "
                          f"{_side(ck.get('cold') or {})} |")
                    W("")
                # ÉCART MAXIMAL sur les contrôles réductibles à UN nombre — CALCULÉ, jamais écrit en dur.
                worst = None
                for ck in checks:
                    h, c = ck.get("hot") or {}, ck.get("cold") or {}
                    hv, cv = h.get("values"), c.get("values")
                    if not (hv and cv and len(hv) == 1 and len(cv) == 1):
                        continue
                    a_, b_ = hv[0], cv[0]
                    if not (isinstance(a_, list) and isinstance(b_, list) and len(a_) == 1 and len(b_) == 1):
                        continue
                    if not (isinstance(a_[0], int) and isinstance(b_[0], int)) or b_[0] <= 0:
                        continue
                    r = a_[0] / b_[0]
                    if worst is None or r > worst[0]:
                        worst = (r, ck, a_[0], b_[0])
                if worst and worst[0] > 1.01:
                    r, ck, hv1, cv1 = worst
                    W(f"**Écart maximal mesuré sur un agrégat scalaire** : `{ck['query']}` sur la fenêtre "
                      f"`{ck['window']}` rend **{fmt_n(hv1)}** sans tier froid et **{fmt_n(cv1)}** avec — "
                      f"soit **x{r:.1f}**. Ce n'est pas une réponse approchée, c'est un mauvais nombre : le")
                    W("chemin d'union hydrate le froid dans une table temporaire SQLite bornée à")
                    W("`PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège")
                    W("SUR CET ÉCHANTILLON.")
                else:
                    W("**Aucun agrégat scalaire ne diverge.** Les contrôles réductibles à un nombre rendent")
                    W("la même valeur des deux côtés, ou bien le côté froid REFUSE de répondre en nommant sa")
                    W("cause. C'est l'invariant de `cold_store/exactness.rs` : aucune valeur dérivée d'un")
                    W("ensemble tronqué n'est rendue comme un nombre.")
                W("")
            else:
                W("| Requête | Fenêtre | Sans tier froid | Avec tier froid | Écart | Tronqué ? |")
                W("|---|:--:|---:|---:|---:|:--:|")
                for ck in checks:
                    # Une requête GXQL contient un `|` : dans une cellule de tableau Markdown il
                    # coupe la ligne en deux. On l'échappe — sinon le tableau se disloque à l'affichage.
                    _q = ck["query"].replace("|", "\\|")
                    W(f"| `{_q}` | {ck['window']} | **{fmt_n(ck['hot_value'])}** | "
                      f"**{fmt_n(ck['cold_value'])}** | x{ck['ratio_hot_over_cold']:.1f} | "
                      f"{'**oui** (' + fmt_n(ck['cold_rows_hydrated']) + ' lignes hydratées)' if ck['cold_truncated'] else 'non'} |")
                W("")
                W("Le chemin d'union chaud∪froid hydrate le froid dans une table temporaire SQLite bornée")
                W("à `PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège")
                W("SUR CET ÉCHANTILLON. Le compte rendu n'est donc pas « approché » : il est **faux d'un")
                W("facteur qui dépend du volume de la fenêtre**. Le daemon le SIGNALE")
                W("(`stats.truncated=true`), mais un lecteur qui ne regarde que le nombre voit un nombre")
                W("faux. Toute latence « froide » de cette passe doit donc être lue avec sa colonne")
                W("« tronqué » : quand elle dit oui, la cellule mesure le temps d'une réponse INCOMPLÈTE,")
                W("et ne peut pas être comparée à la cellule chaude.")
                W("")
            if d.get("_reserve_rollup"):
                W(f"> Réserve : {d['_reserve_rollup']}")
                W("")
        for c in cold_cfgs:
            crows = [r for r in eff if r["config_id"] == c]
            bnd = next((r["cold"].get("boundary_ts") for r in crows
                        if isinstance(r.get("cold"), dict) and r["cold"].get("boundary_ts")), None)
            W(f"### `{c}`")
            W("")
            if bnd:
                W(f"Frontière chaud/froid CALCULÉE PAR LE DAEMON : `boundary_ts={bnd}`. Une fenêtre")
                W("dont la borne basse passe sous cette valeur lit du Parquet ; une fenêtre qui")
                W("l'enjambe lit les DEUX et paie l'union.")
                W("")
            W("| Classe | Fenêtre | p50 | lignes | route | passé par le froid | tronqué |")
            W("|---|:--:|---:|---:|---|---|:--:|")
            for cid, lab, _k in classes:
                for w in wins:
                    r = idx.get((c, cid, w))
                    if not r:
                        continue
                    cold = r.get("cold") if isinstance(r.get("cold"), dict) else None
                    W(f"| `{cid}` | {w} | {fmt_dur(r.get('wall_p50_ms'))} | {fmt_n(r.get('rows'))} | "
                      f"{r.get('served_from') or '—'} | "
                      f"{cold.get('served_from') if cold else 'non'} | "
                      f"{'**oui**' if r.get('truncated') else 'non'} |")
            W("")
            _ev = cfgmeta[c].get("events")
            if cold_age and _ev and _ev == (cold_age[0].get("hot_rows_after")):
                W(f"> Dans le tableau des configurations, la colonne « Événements » de `{c}` vaut "
                  f"{fmt_n(_ev)} : c'est le nombre de lignes CHAUDES, pas la taille du jeu. "
                  f"{fmt_n(cold_age[0].get('hot_rows_before'))} événements sont interrogeables, dont "
                  f"{fmt_n((cold_age[0].get('hot_rows_before') or 0) - _ev)} depuis le Parquet.")
                W("")
            ncold = sum(1 for r in crows if isinstance(r.get("cold"), dict))
            ntrunc = sum(1 for r in crows if r.get("truncated"))
            W(f"**{ncold} cellules sur {len(crows)} ont réellement traversé le tier froid** (colonne")
            W("« passé par le froid » : elle vient de `stats.cold` renvoyé par le daemon, pas de")
            W("l'étiquette de configuration). "
              + (f"**{ntrunc} cellules sont TRONQUÉES** : le chemin d'union hydrate le froid dans "
                 "SQLite avec un plafond de lignes (`PLUME_QUERY_MAX`, défaut 5 000, "
                 "`cold_store/reader.rs:130`) — au-delà, la réponse est PARTIELLE et le daemon le "
                 "dit. Un agrégat sur une fenêtre froide large n'est donc pas exact par défaut : "
                 "c'est le résultat le plus important de cette section."
                 if ntrunc else "Aucune cellule tronquée."))
            W("")

    # ------------------------------------------------------------ PROFIL FLOTTE
    # GARDE : ne comparer que des passes qui ne diffèrent QUE par le nombre de machines. Deux
    # passes à des volumes ou des réglages différents ne mesureraient pas l'effet de la flotte, elles
    # mesureraient leur propre écart. Le critère est DÉRIVÉ des étiquettes de configuration (volume,
    # masquage, FTS, tier froid, sous-ensemble de classes) : aucune liste de configurations en dur.
    def _fleet_key(c):
        m = cfgmeta[c]
        return (m.get("events"), m.get("mask"), m.get("fts_fields"), m.get("cold"), m.get("classes"))
    _groups = {}
    for c in configs:
        if str(cfgmeta[c].get("hosts", "")).isdigit():
            _groups.setdefault(_fleet_key(c), []).append(c)
    _best = max(_groups.values(),
                key=lambda g: len({int(cfgmeta[c]["hosts"]) for c in g}), default=[])
    host_cfgs = _best
    host_vals = sorted({int(cfgmeta[c]["hosts"]) for c in host_cfgs})
    if len(host_vals) >= 2:
        W("## Le nombre de machines — ce que le profil mono-hôte cachait")
        W("")
        W("La production profilée est **mono-nœud** : ses 32 sources ont `distinct_hosts: 1`. `host`")
        W("étant l'une des six colonnes indexées, toute cellule qui filtre ou groupe par hôte y porte")
        W("sur un cas **dégénéré de cardinalité 1**. Les passes ci-dessous rejouent les mêmes classes")
        W("sur des profils FLOTTE dérivés (`bench/make_fleet_profile.py`), **à volume d'événements")
        W("égal**.")
        W("")
        W("**Ce qui change exactement entre ces passes** — il faut le dire avant de lire le tableau :")
        W("**(1)** la cardinalité de `host` (1, puis N) ; **(2)** le MÉLANGE des sources, parce que")
        W("multiplier les sources host-locales par N change leur poids relatif (`auditd` passe de")
        W("38,5 % à 44,7 % du flux). Les deux viennent de la même dérivation. Une classe qui bouge")
        W("peut donc bouger pour l'une OU l'autre raison — sauf les classes `C6*`, qui nomment `host`")
        W("dans la requête : celles-là isolent la cardinalité, et ce sont elles qu'il faut lire pour")
        W("juger du trou de généricité.")
        W("")
        # Ce que le profil FLOTTE dérive en VOLUME. Lu dans le profil lui-même (section `fleet`,
        # `provenance: derived`) : c'est de l'arithmétique sur des distributions mesurées, et le
        # document doit dire lequel des deux il cite.
        import os as _o3
        fl_rows = []
        for c in host_cfgs:
            pn = cfgmeta[c].get("profile")
            if not pn:
                continue
            try:
                with open(_o3.path.join("bench", pn), encoding="utf-8") as fh:
                    fl = json.load(fh).get("fleet") or {}
            except (OSError, ValueError):
                continue
            if fl and not any(r[0] == fl.get("hosts") for r in fl_rows):
                fl_rows.append((fl.get("hosts"), fl.get("events_measured_mono_host"),
                                fl.get("events_fleet_derived"), fl.get("multiplier_effective"),
                                len(fl.get("per_host_sources") or [])))
        if fl_rows:
            W("**Ce que la taille de flotte change en VOLUME** — dérivé (`bench/make_fleet_profile.py`)")
            W("des distributions MESURÉES par source, sur la fenêtre de la production profilée :")
            W("")
            W("| Hôtes | Sources host-locales | Événements mono-hôte (mesuré) | Événements flotte (dérivé) | Facteur |")
            W("|---:|---:|---:|---:|---:|")
            for h, m0, m1, mult, nph in sorted(fl_rows):
                W(f"| {h} | {nph} sur 32 | {fmt_n(m0)} | {fmt_n(m1)} | x{mult} |")
            W("")
            W("La colonne « dérivé » n'est PAS une mesure : c'est la multiplication du poids des")
            W("sources déclarées host-locales par le nombre de machines. Ce qui est mesuré, ce sont")
            W("les distributions de chaque source ; ce qui est déclaré, c'est la liste des sources")
            W("host-locales (`bench/fleet-per-host.txt`, une ligne par source, avec sa raison).")
            W("")
        W("| Classe | Fenêtre | " + " | ".join(f"{h} hôte{'s' if h > 1 else ''}" for h in host_vals) + " |")
        W("|---|:--:|" + "---:|" * len(host_vals))
        by_hosts = {}
        for c in host_cfgs:
            by_hosts.setdefault(int(cfgmeta[c]["hosts"]), []).append(c)
        for cid, lab, _k in classes:
            for w in wins:
                cells = []
                for h in host_vals:
                    r = None
                    for c in by_hosts[h]:
                        r = idx.get((c, cid, w)) or r
                    cells.append(r)
                if sum(1 for x in cells if x and x.get("wall_p50_ms") is not None) < 2:
                    continue
                W(f"| `{cid}` | {w} | "
                  + " | ".join(fmt_dur(x.get("wall_p50_ms")) if x else "—" for x in cells) + " |")
        W("")
        W("Une classe dont la latence ne bouge pas avec le nombre de machines ne dépend pas de la")
        W("cardinalité de `host`. Une classe qui bouge est une classe dont les chiffres publiés sur")
        W("un profil mono-hôte **ne valent pas** pour une flotte — et le sens de l'erreur n'est pas")
        W("toujours le même : là où `host` sert de FILTRE, le mono-hôte est PESSIMISTE (le filtre y")
        W("sélectionne tout, alors qu'il sélectionne 1/N sur une flotte) ; là où `host` sert de clé de")
        W("GROUPEMENT, il est OPTIMISTE (un seul groupe au lieu de N). Un profil mono-hôte ne")
        W("« flatte » donc pas le produit : il le décrit FAUX, dans les deux sens à la fois.")
        W("")

    W("## Le budget de 2 Gio")
    W("")
    peak = max((r.get("peak_rss_bytes") or 0) for r in eff)
    W(f"RSS crête la plus haute observée, toutes cellules confondues : **{peak/2**20:.0f} Mio** "
      f"({peak/BUDGET_BYTES*100:.1f} % du budget de 2 Gio).")
    W("")
    if over:
        W(f"**{len(over)} cellules ont dépassé 2 Gio.** Elles sont listées ici parce qu'un dépassement")
        W("est un résultat, pas un échec à cacher :")
        W("")
        W("| Configuration | Classe | Fenêtre | RSS crête |")
        W("|---|---|:--:|---:|")
        for r in sorted(over, key=lambda x: -(x.get("peak_rss_bytes") or 0)):
            W(f"| `{r['config_id']}` | `{r['class_id']}` | {r['window']} | "
              f"**{fmt_mib(r['peak_rss_bytes'])} Mio** |")
        W("")
    else:
        W("**Aucune cellule n'a dépassé 2 Gio**, et ce n'est pas une déduction : le daemon tournait")
        W("dans un scope `MemoryMax=2G MemorySwapMax=0`, où un dépassement se traduit par un kill du")
        W("noyau, pas par du swap. Il n'a pas été tué.")
        W("")

    render_concurrency(W, conc)

    W("## Cellules à ne pas croire telles quelles")
    W("")
    if superseded:
        W(f"- {superseded} cellules ont été **rejouées** (une mesure bousculée remplacée par une "
          "mesure propre) ; seule la dernière figure dans les tableaux, le JSONL brut garde les deux.")
    for d in deaths:
        W(f"- **Le daemon a été TUÉ après `{d['config_id']}` / `{d['class_id']}` / {d['window']}.** "
          f"{d['note']}")
    
    if swapped:
        W(f"- **{len(swapped)} cellules prises pendant que la machine swappait** "
          f"({', '.join(sorted({r['config_id']+'/'+r['class_id']+'/'+r['window'] for r in swapped}))}). "
          "Un chiffre pris sous swap est faux. Un rejeu a été TENTÉ pour les cellules de la "
          "configuration de référence ; celles qui restent listées ici sont celles pour lesquelles "
          "la machine n'a pas offert de fenêtre sans swap. Leur `p50` est à prendre comme une borne "
          "haute, leur `p95` comme non exploitable.")
    else:
        W("- Aucune cellule n'a été prise pendant que la machine swappait (delta de swap < 8 Mio "
          "sur chaque cellule).")
    if failed:
        W(f"- **{len(failed)} cellules en échec ou en erreur** — elles restent dans le tableau avec "
          "leur message :")
        for r in failed:
            W(f"  - `{r['config_id']}` / `{r['class_id']}` / {r['window']} : "
              f"{'; '.join(r.get('errors') or []) or 'aucun tir réussi'} "
              f"(statuts {r.get('statuses')})")
    else:
        W("- Aucune cellule en erreur.")
    if truncated:
        W(f"- **{len(truncated)} cellules tronquées** par le plafond de lignes "
          "(`PLUME_QUERY_MAX`, 5 000 par défaut) : leur latence est celle d'un résultat PARTIEL.")
    W("")

    # ---------------------------------------------------------------- échelle
    # Deux volumes ou plus : la question posée porte sur « des MILLIONS d'événements », donc ce qui
    # compte n'est pas une latence à un volume, c'est la PENTE. Une cellule absente à l'un des
    # volumes est laissée vide — pas interpolée.
    _f = idx.get((max(configs, key=lambda c: cfgmeta[c].get("events") or 0), "C0-plancher", "all"))
    floor_ms = (_f or {}).get("wall_p50_ms")
    # GARDE : un tableau « d'échelle » ne doit contenir que des passes dont SEUL LE VOLUME diffère.
    # Une passe faite sur un autre PROFIL de données (une flotte de 50 hôtes, par exemple) n'est pas
    # un point de volume : sa colonne `host` n'a pas la même cardinalité, donc l'écart mesuré ne
    # serait pas attribuable au volume. Le critère est DÉRIVÉ de l'étiquette de configuration (nombre
    # d'hôtes du profil), pas d'une liste de configurations à exclure.
    _ref_hosts = cfgmeta.get(ref, {}).get("hosts")
    fts0_vide = [c for c in configs if cfgmeta[c].get("fts_fields") == 0
                 and "non-vide" not in (cfgmeta[c].get("mask") or "")
                 and (_ref_hosts is None or cfgmeta[c].get("hosts") in (None, _ref_hosts))]
    fts0_vide.sort(key=lambda c: cfgmeta[c].get("events") or 0)
    if len(fts0_vide) >= 2:
        W("## Comment la latence monte avec le volume")
        W("")
        W("Mesuré à plusieurs volumes sur la même machine, même binaire, masque vide, "
          "`PLUME_FTS_FIELDS=0`, fenêtre « tout ». C'est la pente qui répond à la question "
          "« des millions d'événements », pas un point isolé.")
        W("")
        W("Réserve à connaître avant de citer ce tableau : les volumes viennent de **passes "
          "distinctes**, donc de bases distinctes et de nombres de répétitions possiblement "
          "différents (la colonne `reps` du JSONL brut le dit cellule par cellule). Les points sont "
          "comparables en ordre de grandeur, pas au pourcentage près. Une case vide = classe non "
          "mesurée à ce volume.")
        W("")
        hdr = " | ".join(f"{fmt_n(cfgmeta[c].get('events'))} lignes" for c in fts0_vide)
        W(f"| Classe | {hdr} | rapport |")
        W("|---" * (len(fts0_vide) + 2) + "|")
        for cid, label, kind in classes:
            vals = [(idx.get((c, cid, "all")) or {}).get("wall_p50_ms") for c in fts0_vide]
            if not any(v is not None for v in vals):
                continue
            ratio = "—"
            if vals[0] and vals[-1]:
                nr = (cfgmeta[fts0_vide[-1]].get("events") or 1) / (cfgmeta[fts0_vide[0]].get("events") or 1)
                ratio = f"x{vals[-1]/vals[0]:.1f} pour x{nr:.1f} de lignes"
                # Si la valeur du PETIT volume est au plancher fixe, le rapport ne mesure pas la
                # pente du scan : il mesure la distance au plancher. On le dit au lieu de laisser
                # citer un « x56 » qui n'a pas le sens qu'on croit.
                if floor_ms and vals[0] <= floor_ms * 1.15:
                    ratio += " ⚠ base au plancher"
            W(f"| `{cid}` | " + " | ".join(fmt_ms(v) for v in vals) + f" | {ratio} |")
        W("")
        W("Une classe dont le rapport de latence suit le rapport de lignes est un **scan** : son coût "
          "est linéaire en volume et rien ne l'indexe. Une classe dont le rapport reste plat est "
          "servie par un index ou par un rollup.")
        W("")
        if floor_ms:
            W(f"⚠ **base au plancher** : au petit volume, la cellule était déjà au plancher fixe "
              f"(~{fmt_dur(floor_ms)}, voir `C0-plancher`). Le rapport affiché mesure alors la "
              "distance à ce plancher, PAS la pente du scan — ne pas le citer comme un facteur "
              "d'échelle.")
        W("")

    # ---------------------------------------------------------------- leviers
    W("## Leviers désignés par la mesure")
    W("")
    W("Aucun n'est implémenté ici : c'est le rôle de l'instrument de les **désigner** et de chiffrer")
    W("le gain qu'on aurait le droit d'en attendre. Classés par gain mesuré décroissant. « Coût RAM »")
    W("dit ce que le levier ajouterait au budget de 2 Gio ; quand il est nul, c'est écrit.")
    W("")

    def cell(cfg, cid, win):
        return idx.get((cfg, cid, win))

    def gain_ms(a, b):
        """a - b en ms, None si l'une des deux cellules manque."""
        if not a or not b or a.get("wall_p50_ms") is None or b.get("wall_p50_ms") is None:
            return None
        return a["wall_p50_ms"] - b["wall_p50_ms"]

    # Base des leviers : la configuration de RÉFÉRENCE = FTS off, masque vide, AU PLUS GROS VOLUME
    # mesuré. Prendre configs[0] (ordre d'apparition) désignerait le plus PETIT volume et sous-
    # estimerait tous les gains.
    def nev(c):
        return cfgmeta[c].get("events") or 0
    cands = [c for c in configs if cfgmeta[c].get("fts_fields") == 0
             and "non-vide" not in (cfgmeta[c].get("mask") or "")]
    # MÊME référence que le verdict : `--ref` si posé, sinon départage par récence (à volume égal,
    # la dernière passe mesurée gagne).
    base = args.ref or max(cands or configs, key=lambda c: (nev(c), configs.index(c)))
    vol = nev(base)
    # Configuration MASQUÉE de référence : la plus grosse mesurée, PAS forcément au volume EXACT de
    # `base`. Exiger `nev(c) == vol` faisait DISPARAÎTRE le levier du masquage dès qu'une nouvelle
    # passe comptait quelques événements de plus (le daemon écrit ses propres traces pendant une
    # passe) — un levier de 36 s s'évaporait pour 4 lignes d'écart. L'écart de volume est REPORTÉ
    # dans le texte du levier plutôt que caché.
    masked = max([c for c in configs if "non-vide" in (cfgmeta[c].get("mask") or "")] or [None],
                 key=lambda c: nev(c) if c else -1)
    fts1 = max([c for c in configs if cfgmeta[c].get("fts_fields") == 1] or [None],
               key=lambda c: nev(c) if c else -1)
    lev = []

    # L1 — le plancher fixe par requête. NE S'ÉMET QUE S'IL EXISTE ENCORE : un levier est une
    # DÉSIGNATION faite par la mesure, donc il doit disparaître du document quand la mesure ne le
    # montre plus. Seuil à 10 ms = bien au-dessus du bruit (le plancher mesuré valait ~51 ms) et bien
    # en dessous du tick de 50 ms qui le causait.
    FLOOR_MIN_MS = 10.0
    fl = cell(base, "C0-plancher", "1h")
    if fl and fl.get("wall_p50_ms") is not None and \
            (fl["wall_p50_ms"] - (fl.get("sql_p50_ms") or 0)) > FLOOR_MIN_MS:
        floor = fl["wall_p50_ms"] - (fl.get("sql_p50_ms") or 0)
        lev.append((floor, "Le plancher fixe par requête",
                    f"une requête dont le SQL coûte {fmt_dur(fl.get('sql_p50_ms'))} revient en "
                    f"{fmt_dur(fl['wall_p50_ms'])} : **{floor:.0f} ms de coût fixe**, indépendant "
                    "du volume. Cause identifiée dans le code : le chien de garde de budget est un "
                    "thread qui boucle sur `sleep(50 ms)` et il est **joint** avant que la réponse "
                    "ne parte (`daemon/src/query_exec.rs:466-537`, `done.store(true)` puis "
                    "`watchdog.join()`). Une attente à condition (condvar avec délai) ou un thread "
                    "non joint rendrait ces millisecondes à **toutes** les requêtes. "
                    "**Coût RAM : nul.** C'est le levier le moins cher du lot, et il domine toutes "
                    "les requêtes rapides — donc toute l'expérience interactive.",
                    "toutes les cellules"))

    # L2 — FTS5 non câblée sur GXQL
    a, b = cell(base, "C2d-free-term-rows", "all"), cell(base, "C2c-fts-bar", "all")
    g = gain_ms(a, b)
    if g is not None:
        lev.append((g, "Câbler FTS5 sur le chemin GXQL",
                    f"la même aiguille, le même nombre de lignes rendues : **{fmt_dur(a['wall_p50_ms'])}** "
                    f"par GXQL (`message LIKE '%…%'`, scan complet) contre "
                    f"**{fmt_dur(b['wall_p50_ms'])}** par `/api/search` (index FTS5 `event_fts`). "
                    "L'index EXISTE et est déjà payé — mesuré en production : 389 Mio, soit 0,61 fois "
                    "le poids de la table — mais il n'est câblé que sur `/api/search`. Sur le chemin "
                    "GXQL, un terme libre devient `col LIKE '%motif%'` "
                    "(`core/src/soql/dialect.rs:65-67`, appelé depuis `soql/mod.rs:881-891`), donc un "
                    "scan complet. **Coût RAM : nul** — l'index est déjà construit et déjà en base.",
                    "C2c vs C2d"))

    # L2bis — LA BORNE TEMPORELLE DÉSARME L'INDEX D'HÔTE. Découvert par les classes `C6*`, qui
    # n'existaient pas avant qu'on mesure autre chose qu'une production mono-nœud. La comparaison
    # est faite entre DEUX FENÊTRES de la MÊME cellule (pas entre deux configurations) : c'est le
    # seul écart du document qui n'oppose pas deux réglages mais deux formes de la même requête.
    _hotw = next((w for w in wins if w not in ("1h", "24h", "all") and not w.startswith("au-dela")), None)
    if _hotw:
        a, b = cell(base, "C6b-groupby-host", _hotw), cell(base, "C6b-groupby-host", "all")
        g = gain_ms(a, b)
        if g is not None and g > 0:
            ratio = (a["wall_p50_ms"] / b["wall_p50_ms"]) if b["wall_p50_ms"] else None
            lev.append((g, "Rendre l'index d'hôte utilisable AVEC une borne temporelle",
                        f"le MÊME `stats count by host`, la MÊME base : **{fmt_dur(b['wall_p50_ms'])}** "
                        f"sans borne de temps contre **{fmt_dur(a['wall_p50_ms'])}** borné à la "
                        f"fenêtre chaude du produit (`{_hotw}`)"
                        + (f", soit **{ratio:.0f}x plus lent**" if ratio else "") + ". Sans borne, le "
                        "group-by est servi par un parcours d'index seul (`idx_event_host` couvre la "
                        "requête). Dès qu'une borne `ts` entre, l'index d'hôte ne suffit plus — il "
                        "faut ouvrir chaque ligne pour lire son `ts` — et la requête redevient un "
                        "scan. Or la borne temporelle est le cas NORMAL : un tableau de bord regarde "
                        "toujours une fenêtre. Voie : un index composite `(host, ts)`, qui rend le "
                        "prédicat de temps satisfiable dans l'index. **Coût RAM : nul ; coût DISQUE : "
                        "un index de plus** (mesuré en production : `idx_event_host` pèse 35,8 Mio "
                        "pour 1,4 M d'événements). À noter : cette cellule est déjà à 64 hôtes ; sur "
                        "une flotte, le nombre de groupes ne fait que grandir.",
                        f"C6b {_hotw} vs all"))

    # L3 — masque non vide qui désarme la route de rollups
    if masked:
        a, b = cell(masked, "C3b-groupby-routable", "all"), cell(base, "C3b-groupby-routable", "all")
        g = gain_ms(a, b)
        if g is not None:
            ratio = (a["wall_p50_ms"] / b["wall_p50_ms"]) if b["wall_p50_ms"] else None
            lev.append((g, "Rendre la route de rollups compatible avec le masquage",
                        f"le MÊME group-by, le MÊME rôle : **{fmt_dur(b['wall_p50_ms'])}** masque vide "
                        f"(servi depuis `{b.get('served_from')}`, {fmt_n(b.get('rows'))} lignes) contre "
                        f"**{fmt_dur(a['wall_p50_ms'])}** masque non vide (servi depuis "
                        f"`{a.get('served_from')}`, {fmt_n(a.get('rows'))} lignes — "
                        "les comptes diffèrent parce que la route de rollups est APPROCHÉE, "
                        "`stats.approx=true` : c'est le prix de sa vitesse)"
                        + (f", soit **{ratio:.1f}x plus lent**" if ratio else "") + ". "
                        "Le rempart de confidentialité est donc aussi un frein de performance : un "
                        "masque non vide désarme la route de rollups (`handlers/query.rs:282`) parce "
                        "que `event_rollup` stocke `src_ip`/`host` en clair. Deux voies : masquer à "
                        "la lecture du rollup, ou matérialiser un rollup par classe de masque. "
                        "**Coût RAM : celui d'un jeu de rollups supplémentaire** (mesuré en "
                        "production : `event_rollup` = 4,4 Mio pour 1,4 M d'événements, donc "
                        "marginal), plus le masquage au vol."
                        + ("" if nev(masked) == vol else
                           f" **Réserve** : la passe masquée porte {fmt_n(nev(masked))} événements "
                           f"contre {fmt_n(vol)} pour la passe non masquée — l'écart de volume est "
                           "négligeable devant le facteur mesuré, mais les deux chiffres ne viennent "
                           "pas de la MÊME passe."),
                        "C3b masqué vs non masqué"))

    # L4 — group-by multi-dim haute cardinalité
    a = cell(base, "C3-groupby-hi", "all")
    b = cell(base, "C3b-groupby-routable", "all")
    if a and a.get("wall_p50_ms") is not None:
        lev.append(((a["wall_p50_ms"] - (b or {}).get("wall_p50_ms", 0)) if b else a["wall_p50_ms"],
                    "Étendre la route de rollups aux dimensions à haute cardinalité",
                    f"`stats count by src_ip,host,source` sur tout l'historique : "
                    f"**{fmt_dur(a['wall_p50_ms'])}**, servi par `{a.get('served_from')}`. Seules "
                    "les formes `by` dont TOUTES les dimensions tiennent dans `{source, severity}` "
                    "sont routables (`rollup_route.rs:349-366`) ; dès qu'une dimension à haute "
                    "cardinalité entre, on retombe sur le scan. **Coût RAM : celui du grain choisi** "
                    "— un rollup à grain `src_ip` est borné en production par "
                    "`PLUME_ROLLUP_SRCIP_TOPN` (50) précisément pour ne pas exploser, ce qui rend le "
                    "résultat approché. Le compromis exactitude/mémoire doit être décidé, pas subi.",
                    "C3-groupby-hi / all"))

    # L5 — regex sur champ étendu non indexé
    a, b = cell(base, "C5b-regex-json-cold", "all"), cell(base, "C5c-eq-json-hot", "all")
    if a and a.get("wall_p50_ms") is not None:
        lev.append((a["wall_p50_ms"] - ((b or {}).get("wall_p50_ms") or 0),
                    "Le champ étendu non indexé n'a aucun chemin d'accès",
                    f"regex sur `fields.object` (aucun index) : **{fmt_dur(a['wall_p50_ms'])}**"
                    + (f" contre **{fmt_dur(b['wall_p50_ms'])}** pour une égalité sur "
                       f"`fields.user`, qui a un index d'expression partiel." if b and b.get("wall_p50_ms") else "")
                    + " Dix champs seulement sont indexés (`HOT_FIELDS` : action, user, owner, kind, "
                    "ns, role, scope, verb, resource, operation) sur les **241 clés distinctes "
                    "mesurées en production**. Pour les 231 autres, toute recherche est un scan avec "
                    "`json_extract` par ligne. C'est exactement la promesse « sur tous les champs » "
                    "qui est en jeu. Voies : `event_fields_fts` (déjà écrit, voir le levier sur le coût de `PLUME_FTS_FIELDS`), ou "
                    "des index d'expression sur demande, ou un stockage colonnaire des champs. "
                    "**Coût RAM : un index d'expression par champ**, à arbitrer — c'est pour ça que "
                    "`PLUME_AUTOINDEX_MAX` existe.",
                    "C5b vs C5c"))

    # L6 — le curseur DEMANDÉ mais pas servi. COMPARAISON LIKE-FOR-LIKE : C4d et C4c posent la MÊME
    # demande (`keyset:true`, limit 200, même filtre) ; la SEULE différence est la projection. Comparer
    # C4b (saut OFFSET à la profondeur 200 000) à C4c (PREMIÈRE page keyset, sans curseur) serait
    # comparer deux profondeurs différentes — c'est ce que faisait la première version de ce document.
    a, b = cell(base, "C4d-keyset-projete", "all"), cell(base, "C4c-raw-keyset", "all")
    g = gain_ms(a, b)
    # MÊME règle que le plancher : un levier est une DÉSIGNATION par la mesure, il doit disparaître
    # quand l'écart n'est plus là. Seuil 20 ms = au-dessus du bruit d'une machine partagée.
    if g is not None and g > 20:
        lev.append((g, "Servir le curseur demandé, y compris quand le pipeline projette",
                    f"MÊME demande (`keyset:true`, limit 200, même filtre), seule la projection "
                    f"change : **{fmt_dur(a['wall_p50_ms'])}** avec `| table …` contre "
                    f"**{fmt_dur(b['wall_p50_ms'])}** sans projection. Le client a demandé une "
                    "pagination par CURSEUR et reçoit une page `OFFSET` : le curseur est désactivé "
                    "dès que le pipeline contient `| table` ou `| fields`, c'est-à-dire dès qu'on "
                    "projette des colonnes — ce que fait toute récupération RAW réelle. "
                    "Conséquences : pas de `next_cursor`, un `total` PLAFONNÉ à 10 000 (des "
                    "événements restent donc cachés) et un coût qui croît avec le numéro de page. "
                    "**Coût RAM : nul.**",
                    "C4d vs C4c"))

    # L7 — coût de PLUME_FTS_FIELDS
    if fts1:
        # La taille de référence FTS-off vient de la configuration FTS-off ELLE-MÊME quand elle
        # existe : c'est la seule valeur dont on est sûr qu'elle a été relevée sur la même base.
        # `db_bytes_fts0` passé à la main n'est qu'un repli.
        d0 = cfgmeta[base].get("db_bytes") or cfgmeta[fts1].get("db_bytes_fts0")
        d1 = cfgmeta[fts1].get("db_bytes")
        cls1 = {r["class_id"] for r in eff if r["config_id"] == fts1}
        peak0 = max((r.get("peak_rss_bytes") or 0) for r in eff
                    if r["config_id"] == base and r["class_id"] in cls1)
        peak1 = max((r.get("peak_rss_bytes") or 0) for r in eff if r["config_id"] == fts1)
        a, b = cell(fts1, "C2d-free-term-rows", "all"), cell(base, "C2d-free-term-rows", "all")
        g = gain_ms(b, a)
        txt = ""
        if d0 and d1:
            txt += (f"activer `PLUME_FTS_FIELDS=1` a fait passer la base de "
                    f"**{fmt_mib(d0)} Mio à {fmt_mib(d1)} Mio** (+{fmt_mib(d1-d0)} Mio, "
                    f"+{(d1-d0)/d0*100:.0f} %). ")
        txt += (f"RSS crête, sur les SEULES classes mesurées dans les deux configurations : "
                f"**{fmt_mib(peak0)} Mio** à `FTS_FIELDS=0` contre **{fmt_mib(peak1)} Mio** à "
                "`FTS_FIELDS=1`. Attention : chaque configuration repart d'un daemon neuf, donc ces "
                "deux crêtes n'ont pas eu le même historique pour monter — l'écart n'est PAS "
                "attribuable au drapeau seul. Le chiffre solide de cette ligne est le coût DISQUE. ")
        if g is not None:
            txt += (f"Écart de latence observé sur le terme libre GXQL (tout l'historique) : "
                    f"**{fmt_dur(abs(g))}** " + ("en faveur de FTS_FIELDS=1" if g > 0 else
                    "en défaveur de FTS_FIELDS=1") + " — mais cet écart ne peut PAS venir du "
                    "drapeau, puisque le chemin GXQL ne lit jamais `event_fields_fts` : c'est du "
                    "bruit de mesure sur une machine partagée, et il est reporté comme tel. ")
        else:
            txt += "Le gain en latence sur le chemin GXQL n'a pas pu être mesuré. "
        txt += ("À retenir : `event_fields_fts` n'est lu que par `/api/search` "
                "(`handlers/search.rs:146-157`). Le chemin GXQL ne le consulte JAMAIS — donc son coût "
                "en disque et en ingest est payé sans que les requêtes GXQL en profitent. C'est le "
                "levier « Câbler FTS5 sur le chemin GXQL » qui rendrait ce coût déjà consenti utile "
                "aux requêtes GXQL.")
        # Cette entrée n'est pas un levier de GAIN : c'est un COÛT mesuré. On la classe en dernier
        # (clé de tri négative) et on remplace l'en-tête « gain » par le coût disque, sinon on
        # publierait « gain : -501 ms », qui ne veut rien dire.
        lev.append((-1e9, "Le coût de `PLUME_FTS_FIELDS=1`, et à qui il profite", txt,
                    "phase 3 vs phase 2",
                    (f"Coût DISQUE mesuré : **+{fmt_mib(d1-d0)} Mio** (+{(d1-d0)/d0*100:.0f} %) "
                     "sur la base. Ce n'est pas un gain, c'est une dépense — et le document dit "
                     "plus bas à qui elle profite.") if (d0 and d1) else None))

    lev = [(t if len(t) == 5 else (t[0], t[1], t[2], t[3], None)) for t in lev]
    for i, (g, title, body, src, override) in enumerate(sorted(lev, key=lambda x: -(x[0] or 0)), 1):
        W(f"### L{i}. {title}")
        W("")
        if override:
            W(f"*{override}*")
        else:
            W(f"*Gain mesuré : **{fmt_dur(g) if g is not None else '—'}** au p50 sur la cellule la "
              f"plus parlante ({src}). Ce n'est pas une promesse de gain : c'est l'écart QUE LA "
              f"MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou "
              f"atteignable.*")
        W("")
        W(body)
        W("")

    W("## Ce qui n'est PAS mesuré ici")
    W("")
    if cold_cfgs:
        W(f"- **Le tier froid au-delà de ce qui est tiré** : {len(cold_cfgs)} configuration(s) tournent")
        W("  `PLUME_COLD_TIER=1` (section dédiée plus haut), mais sur UNE seule taille de fenêtre")
        W("  chaude et UN seul volume. Le moteur vectorisé n'est pas mesuré séparément du chemin")
        W("  d'hydratation : le document ne dit pas lequel a servi chaque cellule au-delà de ce que")
        W("  `stats.cold` en rapporte.")
    else:
        W("- **Le tier froid** (`--features cold_tier` + `PLUME_COLD_TIER=1`) : le binaire est compilé")
        W("  avec la feature, mais toutes les cellules tournent `PLUME_COLD_TIER=0`. Aucun chiffre de ce")
        W("  document ne dit quoi que ce soit du chemin Parquet ni du moteur vectorisé.")
    if conc:
        _cl = sorted({r.get("analysts") for r in conc if r.get("analysts")})
        _sems = sorted({r.get("query_sem") for r in conc if r.get("query_sem")})
        _wins = sorted({r.get("window") for r in conc if r.get("window")})
        W(f"- **La concurrence est mesurée** (section dédiée) : jusqu'à {max(_cl)} analystes")
        W(f"  simultanés, sémaphore {' et '.join(str(s) for s in _sems)}. Ce qui reste hors mesure :")
        W(f"  la concurrence PENDANT une ingestion (les deux charges sont mesurées séparément), la")
        W(f"  charge SOUTENUE sur des heures (chaque niveau dure des dizaines de secondes, pas une")
        W(f"  journée), et les fenêtres autres que {', '.join('`' + w + '`' for w in _wins)} — le")
        W("  mélange est tiré sur la fenêtre la plus coûteuse, pas sur toutes.")
    else:
        W("- **La concurrence** : une requête à la fois. `PLUME_QUERY_CONCURRENCY=3` est en place mais")
        W("  jamais saturé (`sem_wait_ms` reste nul). Le comportement à 10 utilisateurs simultanés n'est")
        W("  pas mesuré.")
    W("- **Le multi-tenant** (`PLUME_MULTI_TENANT=1`) : tout est mesuré en mode 0.")
    W("- **Le cache de pages froid** : impossible de le vider sans privilège root sur la machine de")
    W("  mesure. La colonne `lu` dit ce qui a réellement atteint le disque ; elle ne dit pas ce que")
    W("  ferait un démarrage à froid complet.")
    W("- **La fidélité du texte** : le corps des messages est synthétique. Les chiffres FTS5, `LIKE`")
    W("  et `REGEXP` dépendent directement de ce vocabulaire ; c'est la limite la plus sérieuse du")
    W("  banc et elle est décrite dans `bench/gen_events.py` (`VOCAB`).")
    W("- **`PLUME_AUTOINDEX`** est à 0 (le défaut livré) alors que notre production le met à 1 : les")
    W("  index d'expression auto-créés par l'usage ne sont donc pas dans le tableau.")
    W("")

    W("## Reproduire, et contredire")
    W("")
    W("```sh")
    W("# 1. le profil de données (déjà versionné ; à re-extraire seulement pour une autre prod)")
    W("#    bench/prod-profile.sql, LECTURE SEULE, n'extrait aucune valeur de ligne")
    W("# 2. la matrice complète, de bout en bout :")
    W("CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \\")
    W("    --manifest-path daemon/Cargo.toml")
    W("bench/run.sh                       # 10 M d'événements")
    W("BENCH_EVENTS=1000000 bench/run.sh  # 1 M, pour itérer")
    if conc:
        _cs = ",".join(str(s) for s in sorted({r.get("query_sem") for r in conc if r.get("query_sem")}))
        _cl = ",".join(str(n) for n in sorted({r.get("analysts") for r in conc if r.get("analysts")}))
        W("# 2 bis. la CONCURRENCE, sur une base déjà remplie (redémarre le daemon par valeur de")
        W("#        sémaphore et lui REDEMANDE ce qu'il applique avant de mesurer) :")
        W(f"BENCH_PHASES=concurrency BENCH_SEM_SWEEP={_cs} BENCH_CONC_LEVELS={_cl} bench/run.sh")
    W("# 3. le rendu — LA COMMANDE EXACTE qui a produit CE document, reconstruite depuis ses propres")
    W("#    arguments et pointée sur les données VERSIONNÉES (donc rejouable par un tiers) :")
    for _l in repro_cmd(args):
        W(_l)
    W("```")
    W("")
    W("Cette commande est **régénérée à chaque rendu** : elle ne peut pas se désynchroniser du")
    W("document. C'est délibéré — la version précédente publiait une commande incomplète qui, rejouée")
    W("telle quelle, AMPUTAIT le document de ses sections d'écart et de ses tableaux d'attribution.")
    W("Une commande de reproduction fausse est pire qu'absente : elle fait croire à une")
    W("reproduction réussie.")
    W("")
    W("Le générateur est déterministe : `python3 bench/gen_events.py --count N --end-ts T --digest`")
    W("imprime le SHA-256 du flux. Deux exécutions avec les mêmes paramètres donnent la même")
    W("empreinte — c'est ce qui rend un désaccord sur les chiffres arbitrable.")
    W("")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"écrit {args.out} — {len(eff)} cellules ({superseded} remplacées par rejeu), {len(configs)} configurations, "
          f"{len(over)} au-dessus de 2 Gio, {len(swapped)} sous swap, {len(failed)} en erreur")


if __name__ == "__main__":
    main()
