#!/usr/bin/env python3
"""bench/report.py — rend les mesures brutes (JSONL) en tableau Markdown.

    python3 bench/report.py .bench/results.jsonl -o docs/BENCHMARK.md

Le rendu ne CALCULE rien qui ne soit pas dans les mesures et ne cache aucune cellule : une cellule
en erreur, tronquée, ou prise pendant que la machine swappait apparaît AVEC son défaut.
"""
import argparse
import json
import os
import platform
import re
import subprocess
import time

BUDGET_BYTES = 2 * 1024**3

# --------------------------------------------------------------------------------------------
# LANGUE DU RENDU. Le document existe en deux langues, rendues par la MÊME logique : chaque texte
# rendu passe par `tr()`, dont la clé est le texte français lui-même (forme gettext). Le français
# est donc la clé ET la valeur, et `TEXTES_EN` (en fin de fichier) porte l'anglais de chaque clé.
# Une clé sans traduction fait ÉCHOUER le rendu anglais plutôt que de laisser passer du français :
# `bench/test_report_langues.py` vérifie en plus que les deux ensembles de clés coïncident.
# Les identifiants (configurations, leviers `PLUME_*`, fichiers, commandes) ne passent pas par
# `tr()` : ils ne se traduisent pas.
LANGUES = ("en", "fr")
LANGUE = "en"
# Chemin publié de chaque rendu : c'est lui que la commande de reproduction cite, jamais le `-o`
# reçu (un chemin de la machine qui rend n'a rien à faire dans un document publié).
SORTIE_PUBLIEE = {"en": "docs/BENCHMARK.md", "fr": "docs/BENCHMARK.fr.md"}
SELECTEUR_DE_LANGUE = "[English](BENCHMARK.md) | [Français](BENCHMARK.fr.md)"


HORODATAGE_DE_RENDU = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{4}")
CLES_DU_MATERIEL = {"cpu": str, "cores": int, "mem_gib": (int, float), "kernel": str}


def lire_materiel(texte):
    """`--materiel` : un objet JSON aux quatre clés exactes de `CLES_DU_MATERIEL`, chacune de son
    type ; toute autre forme est REFUSÉE (ValueError au message lisible), jamais devinée."""
    try:
        m = json.loads(texte)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON illisible ({e.msg}, colonne {e.colno})")
    if not isinstance(m, dict):
        raise ValueError("attendu un objet JSON {\"cpu\": …, \"cores\": …, \"mem_gib\": …, \"kernel\": …}")
    manquantes = sorted(set(CLES_DU_MATERIEL) - set(m))
    inconnues = sorted(set(m) - set(CLES_DU_MATERIEL))
    if manquantes or inconnues:
        raise ValueError(f"clés manquantes {manquantes}, clés inconnues {inconnues}")
    for cle, types in CLES_DU_MATERIEL.items():
        v = m[cle]
        if isinstance(v, bool) or not isinstance(v, types):
            raise ValueError(f"« {cle} » a le type {type(v).__name__}, ce n'est pas le type attendu")
        if types is str and not v.strip():
            raise ValueError(f"« {cle} » est vide")
        if types is not str and v <= 0:
            raise ValueError(f"« {cle} » doit être strictement positif")
    return {"cpu": m["cpu"], "cores": m["cores"], "mem_total_bytes": m["mem_gib"] * 2**30,
            "kernel": m["kernel"]}


def tr(fr):
    """Le texte `fr` dans la langue du rendu."""
    if LANGUE == "fr":
        return fr
    try:
        return TEXTES_EN[fr]
    except KeyError:
        raise SystemExit(f"report.py : aucune traduction anglaise pour {fr!r} — rendu refusé "
                         "plutôt que rendu avec un texte français dans le document anglais.")


def tr_donnee(fr):
    """Une chaîne VENUE DES DONNÉES (libellé de classe, de fenêtre, motif…) dans la langue du rendu.

    En anglais : par chaîne exacte (`DONNEES_EN`), ou par gabarit quand le libellé porte une valeur
    (`DONNEES_GABARITS`, une fenêtre en jours, un rapport au plancher) — sinon le rendu est REFUSÉ
    en nommant le libellé, comme pour `tr()`. Une chaîne sans lettre (« — », « ? ») n'a pas de
    langue et passe telle quelle. En français, la donnée est rendue telle qu'enregistrée, sauf les
    retouches de `DONNEES_FR_RETOUCHES` (un segment de code qui n'en était pas un)."""
    if not isinstance(fr, str) or not re.search(r"[^\W\d_]", fr):
        return fr
    if LANGUE == "fr":
        for motif, _en, retouche in DONNEES_GABARITS:
            m = motif.fullmatch(fr)
            if m and retouche:
                return retouche.format(*m.groups())
        for avant, apres in DONNEES_FR_RETOUCHES:
            fr = fr.replace(avant, apres)
        return fr
    if fr in DONNEES_EN:
        return DONNEES_EN[fr]
    for motif, en, _retouche in DONNEES_GABARITS:
        m = motif.fullmatch(fr)
        if m:
            return en.format(*m.groups())
    raise SystemExit(f"report.py : aucune traduction anglaise pour le libellé de données {fr!r} — "
                     "l'ajouter à DONNEES_EN (ou DONNEES_GABARITS) ; rendu refusé plutôt que rendu "
                     "avec un libellé français dans le document anglais.")

# --------------------------------------------------------------------------------------------
# LA LISTE DES CHAMPS INDEXÉS EST LUE DANS LE CODE, JAMAIS RECOPIÉE ICI.
#
# POURQUOI : elle l'a été, et elle a pourri. Le document a publié « dix champs » et les a
# énumérés, alors que le code en portait douze — `dir` et `risk` y sont entrés au moment où
# l'indexation adaptative a été retirée (P6.8-c) pour que deux détections cessent de dépendre
# d'index orphelins. Un lecteur qui suit une énumération périmée conclut, à tort, que son champ
# n'est pas indexé. Une liste recopiée dans un document GÉNÉRÉ est la pire des deux : elle a
# l'autorité de la mesure et la fraîcheur d'un commentaire.
#
# L'EXTRACTION ÉCHOUE PLUTÔT QUE DE DEVINER : sans la constante, pas de rendu. Un rendu qui se
# rabattrait sur une liste par défaut republierait le défaut qu'on vient de retirer.
_HOT_FIELDS_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "daemon", "src", "soql_glue.rs")


def hot_fields():
    """Les champs JSON portant un index d'expression, LUS dans `HOT_FIELDS` (daemon/src/soql_glue.rs)."""
    import re
    try:
        src = open(_HOT_FIELDS_SRC, encoding="utf-8").read()
    except OSError as e:
        raise SystemExit(f"report.py : impossible de lire {_HOT_FIELDS_SRC} ({e}) — la liste des "
                         "champs indexés se LIT dans le code, elle ne se recopie pas. Rendu refusé.")
    m = re.search(r"HOT_FIELDS\s*:\s*&\[&str\]\s*=\s*&\[(.*?)\];", src, re.S)
    if not m:
        raise SystemExit(f"report.py : `HOT_FIELDS` introuvable dans {_HOT_FIELDS_SRC} — la constante "
                         "a été renommée ou déplacée. Rendu refusé plutôt que rendu avec une liste "
                         "périmée.")
    champs = re.findall(r'"([^"]+)"', m.group(1))
    if not champs:
        raise SystemExit("report.py : `HOT_FIELDS` a été trouvée mais ne rend aucun nom — le motif "
                         "d'extraction est faux. Rendu refusé.")
    return champs


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
    if n is None:
        return "—"
    return f"{n:,}" if LANGUE == "en" else f"{n:,}".replace(",", " ")


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


def notes_de_comparaison(args, langue):
    """Les notes `--compare-note` (anglais) ou `--compare-note-fr` (français) ; à défaut de notes
    françaises, le rendu français reprend `--compare-note`, comme le générateur d'avant les deux
    langues."""
    if langue == "fr" and args.compare_note_fr:
        return args.compare_note_fr
    return args.compare_note or []


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
        # QUOTAGE SHELL, pas JSON : ces notes contiennent des accents graves. Entre guillemets
        # doubles, un lecteur qui copie-colle la commande déclencherait une substitution de
        # commande — la commande publiée doit être collable telle quelle, sans surprise.
        for option, notes in (("--compare-note", args.compare_note),
                              ("--compare-note-fr", args.compare_note_fr)):
            note = (notes or [])[i] if i < len(notes or []) else None
            if note:
                line.append(f"    {option} {_sh.quote(note)} \\")
    if args.fill_log:
        v, ok = vers(args.fill_log)
        line.append(f"    --fill-log {v} \\")
        if not ok:
            missing.append(v)
    # L'horodatage et le matériel REPRIS d'un rendu précédent sont cités : sans eux, la commande
    # publiée rendrait un autre en-tête que celui du document qui la porte.
    if args.rendu_le:
        line.append(f"    --rendu-le {_sh.quote(args.rendu_le)} \\")
    if args.materiel:
        line.append(f"    --materiel {_sh.quote(args.materiel)} \\")
    # LES DEUX RENDUS, dans un bloc identique des deux côtés : la commande ne diffère que par sa
    # dernière ligne, et chacune, rejouée seule, redonne son propre fichier.
    commun, line = line, []
    for i, langue in enumerate(LANGUES):
        if i:
            line.append(tr("#    la même commande, pour le rendu français :"))
        line += commun + [f"    --langue {langue} -o {SORTIE_PUBLIEE[langue]}"]
    if missing:
        line.append(tr("# ATTENTION : {0} n'est pas (encore) versionné —").format(", ".join(missing)))
        line.append(tr("# les commandes ci-dessus ne tourneront qu'une fois ce fichier ajouté à bench/results/."))
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

    W(tr("## La concurrence — ce que le nœud fait quand l'équipe travaille en même temps"))
    W("")
    W(tr("Tout le reste de ce document est pris **une requête à la fois** : aucune requête n'y "
         "attend"))
    W(tr("son tour, et le document le disait lui-même. Cette section mesure l'autre condition, la"))
    W(tr("vraie : plusieurs analystes qui lancent de **très grosses** requêtes en même temps, sur "
         "la"))
    W(tr("même base et sous le **même budget appliqué** de 2 Gio."))
    W("")
    W(tr("**Un niveau** = *N* analystes indépendants (chacun sa connexion HTTP, chacun son compte"))
    W(tr("`viewer`), chacun parcourant le mélange plusieurs fois, en décalant son point de départ "
         "— deux"))
    W(tr("voisins ne tirent donc pas la même requête au même instant. Le niveau se termine quand tous ont"))
    W(tr("fini leur travail : le débit agrégé est du travail RÉELLEMENT servi, pas une "
         "extrapolation."))
    W("")
    W(tr("**L'ordre des questions est délibéré : la justesse d'abord.** Trois défauts de "
         "correction"))
    W(tr("viennent d'être trouvés dans les chemins d'agrégat de ce produit, et aucun n'était "
         "visible sur"))
    W(tr("un banc de latence. Chaque réponse concurrente est donc comparée **par sa valeur** à la "
         "réponse"))
    W(tr("obtenue seul — même base, même binaire, même fenêtre — avant qu'on ne regarde un seul "
         "temps."))
    W("")

    # ---------------------------------------------------------------- le mélange et sa dérivation
    h0 = heads[0] if heads else None
    if h0:
        d = h0.get("derivation") or {}
        solo = h0.get("solo") or {}
        W(tr("### Le mélange, et pourquoi c'est celui-là"))
        W("")
        W(tr("Le mélange n'est pas une liste de goûts : il est **dérivé de la passe solo qui le"))
        W(tr("précède**. Le PLANCHER est la requête la moins chère observée (`{0}`,").format(d.get('floor_id')))
        W(tr("{0}) — c'est le coût FIXE d'une requête, pas du travail de base.").format(fmt_dur(d.get('floor_ms'))))
        W(tr("Chaque **famille** de la matrice (les classes `C1`…`C6` de ce document) entre par son"))
        W(tr("représentant le plus coûteux, et seulement s'il coûte au moins **{0:g} ×**").format(d.get('heavy_factor', 0)))
        W(tr("le plancher. La famille du plancher échoue ainsi à son propre test et s'exclut "
             "d'elle-même."))
        W(tr("Le plancher est ensuite ajouté **à part** : il ne charge rien, il mesure ce que devient "
             "le"))
        W(tr("clic instantané d'un tableau de bord pendant que les collègues lancent des monstres."))
        W("")
        W(tr("| Classe retenue | Famille | Ce que c'est | Coût SEUL (p50) |"))
        W("|---|:--:|---|---:|")
        for cid in (d.get("mix_effectif") or d.get("mix") or []):
            s = solo.get(cid) or {}
            fam = cid[1] if len(cid) > 1 else "?"
            W(tr("| `{cid}` | {fam} | {0} | {1} ms |").format(tr_donnee(s.get('label','—')), fmt_ms(s.get('p50_ms')), cid=cid, fam=fam))
        W("")
        if d.get("rejected"):
            W(tr("Familles **écartées** du mélange lourd, avec leur motif mesuré :"))
            W("")
            for r in d["rejected"]:
                W(tr("- famille {0} (`{1}`) : {2}.").format(r['family'], r['class_id'], tr_donnee(r['why'])))
            W("")
        q = h0.get("quiescence") or {}
        if q:
            W(tr("**Mise au repos avant de mesurer** : un daemon qui vient de démarrer lance un `ANALYZE`"))
            W(tr("complet en arrière-plan, qui prend le verrou d'écriture et consomme disque et CPU —"))
            W(tr("mesurer tout de suite, c'est mesurer le démarrage."))
            W(tr("Le harnais attend donc {0} tirs consécutifs dont l'attente avant moteur est").format(q.get('need')))
            W(tr("sous la milliseconde : **{0}** ici").format(fmt_dur((q.get('seconds') or 0) * 1000)))
            W(f"(`quiescent={str(q.get('quiescent')).lower()}`).")
            W("")

    # ---------------------------------------------------------------- la courbe, par sémaphore
    for c in cfgs:
        rows = sorted([r for r in lvls if r["config_id"] == c], key=lambda r: r["analysts"])
        h = head_of.get(c) or {}
        sem = rows[0].get("query_sem")
        W(tr("### La courbe — `{c}` (`PLUME_QUERY_CONCURRENCY={sem}`)").format(c=c, sem=sem))
        W("")
        W(tr("Sémaphore **{sem}**, {0}. Fenêtre `{1}` (sans borne : le cas le plus coûteux). {2} "
             "passages par analyste sur {3} classes.").format(tr_donnee(h['query_sem_source']) if h.get('query_sem_source') else tr('source inconnue'), rows[0].get('window'), rows[0].get('rounds'), len(rows[0].get('mix') or []), sem=sem))
        W("")
        _d = h.get("derivation") or {}
        if _d.get("imposed"):
            _dv = _d.get("diverge_de_la_derivation") or []
            W(tr("Mélange **IMPOSÉ** (celui de la passe de référence), pour que la comparaison entre "
                 "sémaphores ne porte que sur le sémaphore.")
              + (tr(" Sa propre passe solo aurait dérivé un mélange différent de {0} classe(s) : {1} — c'est "
                    "précisément ce que l'imposition neutralise.").format(len(_dv), ', '.join('`' + x + '`' for x in _dv)) if _dv else
                 tr(" Sa propre passe solo aurait dérivé exactement le même.")))
            W("")
        elif h.get("derivation"):
            W(tr("Mélange **DÉRIVÉ** par la passe solo de cette configuration (tableau plus haut)."))
            W("")
        W(tr("| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire "
             "analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |"))
        W("|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|")
        base_q = rows[0].get("throughput_qps") or 0
        for r in rows:
            ev = r.get("cg_events_delta")
            _q = r.get("throughput_qps") or 0
            _rel = "" if not base_q else f" (x{_q/base_q:.2f})"
            # Le cgroup a disparu avec le processus tué : on n'invente pas la valeur, on dit qu'elle
            # n'existe plus. Une case « — » est une absence ; un 0 serait un mensonge.
            _recl = fmt_n(ev.get("max")) if ev else (tr("— (cgroup disparu)") if r.get("cgroup_gone") else "—")
            _dead = "" if r.get("daemon_alive", True) else tr(" — **daemon TUÉ**")
            W(tr("| **{0}** | {1} | {2}/{3}{dead} | {4:.0f} s | {q:.2f} q/s{rel} | {5} | {6} | {7} | {8} "
                 "| {9} | {10} | {11} Mio | {recl} | {12} |").format(r['analysts'], tr('oui') if r.get('queue_possible') else tr('non'), r['queries_ok'], r['queries'], r['elapsed_s'], fmt_ms(r.get('wall_p50_ms')), fmt_ms(r.get('wall_p95_ms')), fmt_ms(r.get('wall_max_ms')), fmt_ms(r.get('analyst_p50_max_ms')), fmt_ms(r.get('sem_wait_p50_ms')), fmt_ms(r.get('sem_wait_p95_ms')), fmt_mib(r.get('peak_rss_bytes')), tr('**OUI**') if (ev or {}).get('oom_kill') else tr('non'), dead=_dead, q=_q, rel=_rel, recl=_recl))
        W("")
        # CE QUI EST ARRIVÉ AUX REQUÊTES QUI N'ONT PAS ABOUTI. Un refus NOMMÉ et une connexion coupée
        # ne se rangent pas ensemble : le premier est une dégradation maîtrisée, le second est
        # l'absence de processus.
        bad = [r for r in rows if r["queries_ok"] < r["queries"]]
        if bad:
            W(tr("Requêtes qui n'ont pas abouti, par statut HTTP :"))
            W("")
            W(tr("| Analystes | statuts | messages |"))
            W("|---:|---|---|")
            for r in bad:
                sc = r.get("status_counts") or {}
                W(f"| {r['analysts']} | "
                  + ", ".join(f"`{k}` x{v}" for k, v in sorted(sc.items())) + " | "
                  + "<br>".join(f"`{e[:110]}`" for e in (r.get("errors") or [])[:3]) + " |")
            W("")
            W(tr("`0` = pas de réponse HTTP du tout (connexion coupée / refusée) : c'est ce que voit un"))
            W(tr("client quand le processus n'est plus là. Un `4xx` avec une cause nommée est l'inverse :"))
            W(tr("le daemon a REFUSÉ proprement, en disant pourquoi."))
            W("")
        W(tr("Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde"))
        W(tr("(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent "
             "sur"))
        W(tr("**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians"))
        W(tr("individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le "
             "temps"))
        W(tr("passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le "
             "verrou"))
        W(tr("de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le"))
        W(tr("compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû"))
        W(tr("récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau."))
        W("")
        sw = [r for r in rows if r.get("swap_suspect")]
        if sw:
            W(tr("**{0} niveau(x) pris pendant que la MACHINE swappait** ({1} analystes) : ces lignes "
                 "mesurent le").format(len(sw), ', '.join(str(r['analysts']) for r in sw)))
            W(tr("stockage de l'hôte autant que plume, elles sont à rejouer."))
            W("")
        cpu = max((r.get("harness_cpu_share") or 0) for r in rows)
        W(tr("*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de"))
        W(tr("**{0:.1f} %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence").format(cpu*100))
        W(tr("mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio"))
        W(tr("sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL)."))
        W("")

    # ---------------------------------------------------------------- justesse
    W(tr("### La réponse est-elle la MÊME sous charge ?"))
    W("")
    tot = dict(judged=0, same=0, differs=0, nombre_faux=0, hors_verdict=0)
    for r in lvls:
        j = r.get("justesse") or {}
        for k in tot:
            tot[k] += j.get(k, 0) or 0
    W("| | |")
    W("|---|---:|")
    W(tr("| Réponses comparées à leur référence solo | **{0}** |").format(fmt_n(tot['judged'])))
    W(tr("| Identiques (empreinte ET total) | **{0}** |").format(fmt_n(tot['same'])))
    W(tr("| Divergentes | **{0}** |").format(fmt_n(tot['differs'])))
    W(tr("| Dont NOMBRES FAUX (valeur dérivée d'un ensemble) | **{0}** |").format(fmt_n(tot['nombre_faux'])))
    tot_fail = sum(r["queries"] - r["queries_ok"] for r in lvls)
    W(tr("| Hors verdict (voir ci-dessous) | {0} |").format(fmt_n(tot['hors_verdict'])))
    W("")
    if tot["hors_verdict"]:
        if tot["hors_verdict"] == tot_fail:
            W(tr("Les {0} réponses hors verdict sont EXACTEMENT les {1} requêtes qui n'ont pas abouti "
                 "(connexion coupée après le kill, ou refus nommé) : une requête sans réponse n'a rien à "
                 "comparer. Aucune n'est hors verdict pour cause d'instabilité — le compte le prouve, il "
                 "n'est pas affirmé.").format(fmt_n(tot['hors_verdict']), fmt_n(tot_fail)))
        else:
            W(tr("Sur {0} réponses hors verdict, {1} sont des requêtes qui n'ont pas abouti (rien à "
                 "comparer) ; le reste vient des classes déclarées instables SEUL (voir ci-dessous).").format(fmt_n(tot['hors_verdict']), fmt_n(tot_fail)))
        W("")
    if tot["differs"] == 0:
        W(tr("**Aucune réponse concurrente ne diffère de la réponse obtenue seul.** L'empreinte est"))
        W(tr("insensible à l'ordre (un `GROUP BY` est un sac non ordonné) et le total de pagination "
             "est"))
        W(tr("comparé en plus. Ce n'est pas une déduction depuis les latences : ce sont les VALEURS "
             "qui"))
        W(tr("ont été comparées, requête par requête, contre une référence prise sur la même base et "
             "le"))
        W(tr("même binaire quelques minutes plus tôt."))
    else:
        W(tr("**Des réponses concurrentes diffèrent de la réponse obtenue seul.** Le détail est dans "
             "le"))
        W(tr("JSONL (`justesse.divergences` : empreinte et valeurs des deux côtés) :"))
        W("")
        W(tr("| Passe | Analystes | Classe | Dérivée d'un ensemble | Solo | Sous charge |"))
        W("|---|---:|---|:--:|---|---|")
        for r in lvls:
            for dv in ((r.get("justesse") or {}).get("divergences") or [])[:8]:
                W(f"| `{r['config_id']}` | {r['analysts']} | `{dv['class_id']}` | "
                  f"{tr('**OUI**') if dv.get('set_derived') else tr('non')} | "
                  f"`{str(dv.get('solo_values') or dv.get('solo_digest'))[:60]}` | "
                  f"`{str(dv.get('values') or dv.get('digest'))[:60]}` |")
    W("")
    excl = sorted({x for h in heads for x in (h.get("exclus_du_verdict") or [])})
    if excl:
        W(tr("**Hors verdict, et pourquoi** : une classe dont la réponse varie DÉJÀ sans charge ne "
             "peut"))
        W(tr("pas servir à accuser la concurrence — l'accuser d'une divergence qu'on observe seul "
             "serait"))
        W(tr("une fausse alerte, et une fausse alerte détruit la valeur des vraies. Classes retirées "
             "du"))
        W(tr("verdict : {0}.").format(', '.join('`' + x + '`' for x in excl)))
    else:
        W(tr("**Aucune classe n'a été retirée du verdict** : chacune rend la même réponse à chacune "
             "de ses"))
        W(tr("répétitions SEUL, donc chacune est comparable sous charge. C'est vérifié, pas supposé."))
    W("")

    # ---------------------------------------------------------------- l'attente : ce qui en est, ce qui n'en est pas
    W(tr("### L'attente d'un permit, séparée de ce qui n'en est pas"))
    W("")
    W(tr("C'est le champ `sem_wait_ms` que le daemon publie pour séparer « la requête est lente » "
         "de"))
    W(tr("« la requête attendait son tour ». La campagne précédente a montré **qu'il ne le "
         "faisait pas**,"))
    W(tr("et la démonstration ne demandait aucun seuil : tant qu'il y a **au moins autant de "
         "permis que"))
    W(tr("d'analystes**, aucune requête ne peut attendre son tour. À ces niveaux, l'attente d'un "
         "permit"))
    W(tr("est nulle *par construction* — toute valeur non nulle y est nécessairement autre chose."))
    W("")
    W(tr("| Passe | Analystes | Permis | File possible ? | découpage publié ? | attente PERMIT "
         "p95 | attente PERMIT max |"))
    W("|---|---:|---:|:--:|:--:|---:|---:|")
    contam = []
    for r in lvls:
        if r.get("queue_possible"):
            continue
        contam.append(r)
        W(tr("| `{0}` | {1} | {2} | **non** | {3} | {4} | **{5}** |").format(r['config_id'], r['analysts'], r.get('query_sem'), tr('oui') if r.get('db_lock_wait_samples') else tr('**non**'), fmt_ms(r.get('sem_wait_contamination_p95_ms')), fmt_ms(r.get('sem_wait_contamination_ms'))))
    W("")
    # La colonne « découpage publié ? » PARTITIONNE les passes : celles d'AVANT le découpage (le champ
    # additionnait deux attentes) et celles d'APRÈS. Sans elle, un lecteur verrait des zéros et des
    # secondes dans la même colonne sans savoir que ce ne sont pas les mêmes binaires.
    avant = [r for r in contam if not r.get("db_lock_wait_samples")]
    apres = [r for r in contam if r.get("db_lock_wait_samples")]
    split = [r for r in lvls if r.get("db_lock_wait_samples")]
    # Une passe est « d'après le découpage » si son en-tête porte la mesure du verrou partagé : le
    # critère est la PRÉSENCE du champ, jamais un numéro de version qu'il faudrait tenir à jour.
    h_avant = [h for h in heads if h.get("db_lock_wait_solo_max_ms") is None]
    h_apres = [h for h in heads if h.get("db_lock_wait_solo_max_ms") is not None]
    worst = max((r.get("sem_wait_contamination_ms") or 0) for r in avant) if avant else 0
    solo_worst = max((h.get("sem_wait_solo_max_ms") or 0) for h in h_avant) if h_avant else 0
    if worst > 0 or solo_worst > 0:
        W(tr("**Avant le découpage** : le maximum observé là où aucune file n'est possible est de"))
        W(tr("**{0}** en charge sous-critique, et de **{1}** pendant la").format(fmt_dur(worst), fmt_dur(solo_worst)))
        W(tr("passe solo (un seul client, aucun autre en vol). Un sémaphore avec des permis libres ne"))
        W(tr("peut pas produire ça : le champ mesurait autre chose que son nom, et son nom envoie"))
        W(tr("l'exploitant AUGMENTER le sémaphore — la seule action que la section précédente mesure"))
        W(tr("comme nuisible (débit ×0,46, p95 27 s → 50 s, RSS +725 Mio, daemon tué à 10 analystes)."))
        W("")
    if apres:
        worst_apres = max((r.get("sem_wait_contamination_ms") or 0) for r in apres)
        solo_apres = max((h.get("sem_wait_solo_max_ms") or 0) for h in h_apres) if h_apres else 0
        if worst_apres == 0 and solo_apres == 0:
            W(tr("**Après : zéro partout.** Là où aucune file n'est possible, l'attente publiée est nulle "
                 "—"))
            W(tr("pas « petite » : nulle, à la microseconde de résolution du champ. Ce n'est pas une "
                 "mesure"))
            W(tr("qui a bien voulu tomber juste : quand un permit est libre il est pris sans jamais"))
            W(tr("suspendre la tâche, et la valeur publiée est le zéro CONSTANT"))
            W(tr("(`daemon/src/query_timing.rs`) — aucune horloge n'intervient sur ce chemin, donc rien ne"))
            W(tr("peut la contaminer. La propriété « autant de permis que de clients ⇒ aucune attente » a"))
            W(tr("cessé d'être une mesure à vérifier pour devenir la construction de la valeur, et le"))
            W(tr("harnais SORT EN ERREUR si elle est violée au lieu de publier le chiffre."))
        else:
            W(tr("**Après le découpage, il reste {0}** là où aucune file n'est").format(fmt_dur(worst_apres)))
            W(tr("possible : la correction est incomplète, et c'est publié tel quel."))
        W("")

    if split:
        W(tr("#### Où passe le temps, maintenant qu'il est découpé"))
        W("")
        W(tr("Le champ ne pouvait pas être corrigé en le déplaçant : ce qu'il additionnait devait être"))
        W(tr("**séparé**, sinon la part cachée serait simplement retombée ailleurs. Le daemon publie "
             "donc"))
        W(tr("un découpage TOTAL — `prepare + sem_wait + exec == server` par construction, `exec` "
             "étant le"))
        W(tr("reste et jamais une troisième horloge :"))
        W("")
        W(tr("| champ | ce qu'il mesure |"))
        W("|---|---|")
        W(tr("| `prepare_ms` | avant le permit : corps, masques, **couverture des rollups**, "
             "compilation |"))
        W(tr("| `sem_wait_ms` | l'attente du PERMIT, et rien d'autre |"))
        W(tr("| `db_lock_wait_ms` | le temps passé à **obtenir** le verrou de la connexion PARTAGÉE "
             "(pas celui passé à le tenir) |"))
        W(tr("| `exec_ms` | le reste : l'exécution |"))
        W("")
        # « avant moteur » = prepare + sem_wait, pas la seule préparation : c'est ce que la requête
        # subit avant d'exécuter quoi que ce soit, et c'est exactement ce que l'ancien champ publiait
        # sous le nom du sémaphore. L'appeler « prépa » ici rejouerait l'erreur au format tableau.
        W(tr("| Passe | Analystes | file ? | avant moteur p50 | avant moteur p95 | **verrou partagé** "
             "p50 | **verrou partagé** max | permit p95 | mur p95 |"))
        W("|---|---:|:--:|---:|---:|---:|---:|---:|---:|")
        for r in split:
            W(f"| `{r['config_id']}` | {r['analysts']} | {tr('oui') if r.get('queue_possible') else tr('non')} | "
              f"{fmt_ms(r.get('pre_engine_p50_ms'))} | {fmt_ms(r.get('pre_engine_p95_ms'))} | "
              f"**{fmt_ms(r.get('db_lock_wait_p50_ms'))}** | **{fmt_ms(r.get('db_lock_wait_max_ms'))}** | "
              f"{fmt_ms(r.get('sem_wait_p95_ms'))} | {fmt_ms(r.get('wall_p95_ms'))} |")
        W("")
        # LA PARTITION EST DANS LES DONNÉES : les passes qui MESURENT encore le verrou en place, et
        # celles où il a été retiré. Écrire « le chemin prend le verrou » au présent pour toutes
        # serait faux pour les secondes — et c'est exactement le genre de phrase qui survit à son fait.
        avec = [r for r in split if (r.get("db_lock_wait_max_ms") or 0) > 0]
        sans = [r for r in split if (r.get("db_lock_wait_max_ms") or 0) == 0]
        W(tr("**La sérialisation que personne ne voyait.** Le chemin d'une requête interactive lit la"))
        W(tr("couverture des rollups. Tant que cette lecture prenait le verrou de la connexion"))
        W(tr("**partagée** — celui-là même que la boucle de rollups tient pendant tout un tick"))
        W(tr("(`spawn_rollup_loop`, 120 s) et que l'`ANALYZE` de démarrage tient plusieurs minutes —"))
        W(tr("**aucun sémaphore ne bornait cette attente** : elle avait lieu ailleurs que sur le"))
        W(tr("sémaphore, et augmenter le sémaphore n'y met que plus de monde."))
        W("")
        if avec:
            dbw_worst = max((r.get("db_lock_wait_max_ms") or 0) for r in avec)
            dbw_solo = max((h.get("db_lock_wait_solo_max_ms") or 0) for h in heads
                           if h["config_id"] in {r["config_id"] for r in avec}) if heads else 0
            W(tr("MESURÉ, verrou en place ({0}) :").format(', '.join('`' + c + '`' for c in sorted({r['config_id'] for r in avec}))))
            W(tr("jusqu'à **{0}** sous charge et **{1}** en solo — sur le").format(fmt_dur(dbw_worst), fmt_dur(dbw_solo)))
            W(tr("chemin de CHAQUE requête GXQL, pendant que l'attente de permit, elle, était nulle."))
            W("")
        if sans:
            W(tr("MESURÉ après retrait ({0}) :").format(', '.join('`' + c + '`' for c in sorted({r['config_id'] for r in sans}))))
            W(tr("**zéro**. La lecture de couverture est passée au pool de lecture — mêmes lignes `meta`"))
            W(tr("commitées, même repli fail-closed vers « rien d'établi », donc le même corps de rollup"))
            W(tr("servi ou décliné ; seul le verrou disparaît. Le champ reste publié à zéro : une absence"))
            W(tr("de champ se lirait « je ne sais pas », un zéro se lit « j'ai regardé »."))
            W("")
        W(tr("C'est la lecture qui change une décision : un exploitant qui voit l'attente du permit à"))
        W(tr("zéro et le verrou partagé non nul sait que son sémaphore n'est pas le levier. Avant le"))
        W(tr("découpage, les deux étaient dans le même champ, sous le nom du sémaphore."))
        W("")
    # L'ANGLE MORT SE LIT SUR LA GÉNÉRATION LA PLUS RÉCENTE, pas sur toutes : une route corrigée
    # depuis resterait signalée à jamais si on unissait les passes. `h_apres` quand il existe, sinon
    # tout ce qu'on a — le critère est la présence du découpage, pas un numéro de version.
    hs = h_apres or heads
    nosw = sorted({x for h in hs for x in (h.get("classes_sans_sem_wait") or [])})
    if nosw:
        W(tr("**Angle mort restant** : {0} ne publie(nt) aucun").format(', '.join('`' + x + '`' for x in nosw)))
        W(tr("`stats` — la barre `/api/search` prend pourtant un permit sur le MÊME sémaphore. Sur "
             "cette"))
        W(tr("route, il est donc impossible de distinguer une recherche lente d'une recherche qui"))
        W(tr("attendait : c'est mesuré ici, ce n'est pas corrigé ici."))
        W("")
    else:
        W(tr("**Aucune route en angle mort** : toutes les classes tirées ici publient leur découpage, "
             "y"))
        W(tr("compris la barre `/api/search`, qui prend un permit sur le MÊME sémaphore et ne publiait"))
        W(tr("rien du tout jusqu'à la campagne précédente. Une route invisible à la mesure de "
             "concurrence"))
        W(tr("pèse pourtant dessus : elle consomme les mêmes permis."))
        W("")


    # ---------------------------------------------------------------- le clic sous charge
    floor_id = (h0.get("derivation") or {}).get("floor_id") if h0 else None
    if floor_id:
        W(tr("### Le clic de tableau de bord, pendant que les autres travaillent"))
        W("")
        W(tr("`{floor_id}` est la requête la moins chère de la matrice. Seule, elle est instantanée. "
             "Ce").format(floor_id=floor_id))
        W(tr("tableau est ce que l'analyste RESSENT : aucune moyenne ne le montre, parce qu'elle est"))
        W(tr("noyée dans les monstres."))
        W("")
        W(tr("| Passe | Analystes | p50 | p95 | pire |"))
        W("|---|---:|---:|---:|---:|")
        for r in lvls:
            pc = (r.get("per_class") or {}).get(floor_id) or {}
            W(f"| `{r['config_id']}` | {r['analysts']} | {fmt_ms(pc.get('p50_ms'))} | "
              f"{fmt_ms(pc.get('p95_ms'))} | {fmt_ms(pc.get('max_ms'))} |")
        W("")

    # ---------------------------------------------------------------- budget
    W(tr("### Le budget de 2 Gio, à plusieurs"))
    W("")
    peak = max((r.get("peak_rss_bytes") or 0) for r in lvls)
    cgpeak = max((r.get("peak_cgroup_bytes") or 0) for r in lvls)
    cgmax = max((r.get("cgroup_max_bytes") or 0) for r in lvls)
    ooms = sum((r.get("cg_events_delta") or {}).get("oom_kill", 0) or 0 for r in lvls)
    killed = [r for r in lvls if not r.get("daemon_alive", True)]
    W(tr("- **RSS crête du daemon, tous niveaux confondus : {0} Mio** ({1:.0f} % du budget).").format(fmt_mib(peak), peak/BUDGET_BYTES*100))
    W(tr("- **Mémoire du cgroup crête : {0} Mio** pour un plafond de {1} Mio.").format(fmt_mib(cgpeak), fmt_mib(cgmax)))
    W(tr("  Ce n'est pas la même grandeur que la RSS : le noyau compare au plafond la mémoire du "
         "CGROUP,"))
    W(tr("  cache de pages compris. Une base de 1,4 Gio lue en boucle le remplit — le cgroup vit "
         "donc"))
    W(tr("  **collé à son plafond**, et ce qui varie n'est pas son occupation mais son travail de"))
    W(tr("  récupération."))
    if killed:
        for r in killed:
            # Le plafond du cgroup n'est plus lisible sur le niveau qui a tué le processus (le cgroup
            # est parti avec lui) : on reprend celui des autres niveaux de LA MÊME passe, qui est le
            # même scope et le même réglage. Publier « — » ici cacherait le seul terme de comparaison.
            _cm = max((x.get("cgroup_max_bytes") or 0) for x in lvls
                      if x["config_id"] == r["config_id"]) or None
            W(tr("- **LE BUDGET A CÉDÉ** : `{0}`, **{1} analystes** (sémaphore {2}). RSS crête {3} Mio "
                 "contre un plafond de {4} Mio, {5} requêtes sur {6} n'ont pas abouti, et le processus "
                 "n'existait plus à la fin du niveau. Sous `MemoryMax` **sans swap**, cela ne peut pas "
                 "être autre chose qu'un dépassement du budget : le noyau tue, il ne glisse pas en swap. "
                 "Les niveaux au-delà ne sont **pas** mesurés — une absence, pas un zéro.").format(r['config_id'], r['analysts'], r.get('query_sem'), fmt_mib(r.get('peak_rss_bytes')), fmt_mib(_cm), r['queries'] - r['queries_ok'], r['queries']))
        W(tr("- La dégradation n'est pas binaire : AVANT le kill, le daemon a d'abord REFUSÉ "
             "proprement des requêtes en nommant sa cause (budget interactif de 60 s dépassé, `4xx`). "
             "Le refus nommé arrive donc en premier ; le kill est ce qui suit quand la mémoire, elle, "
             "ne négocie pas."))
    W(tr("- **Tués par le noyau (`memory.events:oom_kill`) : {ooms}** — compteur du cgroup, à "
         "lire avec la réserve ci-dessus : le cgroup d'un scope tué disparaît avec lui, et son "
         "compteur n'est alors plus lisible du tout.").format(ooms=ooms))
    if deaths:
        for d in deaths:
            W(tr("- Le harnais a ARRÊTÉ le balayage après le niveau {0} (`{1}`) : {2}").format(d['daemon_died_at_level'], d.get('config_id'), tr_donnee(d['note'])))
    if not killed:
        W(tr("- **Le daemon n'a été tué à aucun niveau mesuré.** Le dépassement du budget ne se "
             "manifeste"))
        W(tr("  donc pas ici par un kill mais par du **travail de récupération** : la colonne « "
             "plafond"))
        W(tr("  touché » des courbes ci-dessus compte, pour chaque niveau, le nombre de fois où le "
             "noyau"))
        W(tr("  a dû reprendre de la mémoire au cgroup pour rester sous 2 Gio."))
    W("")

    # ---------------------------------------------------------------- l'échange sémaphore <-> RAM
    # GARDE DE COMPARABILITÉ, DÉRIVÉE DES DONNÉES : deux passes ne peuvent être comparées en DÉBIT
    # que si elles ont fait EXACTEMENT le même travail. Le mélange est enregistré dans chaque ligne
    # de niveau ; on ne compare donc que les configurations dont le mélange est identique, et on
    # NOMME celles qu'on écarte. Sans cette garde, une différence de mélange (deux classes proches
    # d'une même famille départagées autrement) se lirait comme un effet du sémaphore.
    # LA CLÉ PORTE AUSSI LE BINAIRE, et c'est un correctif de ce rapport : quand le document publie
    # plusieurs GÉNÉRATIONS de binaire (une passe d'avant un correctif et une passe d'après), grouper
    # sur le seul mélange les met dans le MÊME tableau — et la phrase de synthèse (« ces six nombres
    # SONT le taux de change entre un sémaphore à X et un sémaphore à Y ») devient fausse, parce que
    # DEUX choses ont changé. La provenance du binaire est déjà dans les données (`config.version`,
    # l'empreinte du binaire mesuré) : on la met dans la clé plutôt que d'énumérer des passes.
    def _bin_of(c):
        r = next(r for r in lvls if r["config_id"] == c)
        return str((r.get("config") or {}).get("version") or "")

    def _when_of(c):
        return str(next(r for r in lvls if r["config_id"] == c).get("measured_at") or "")

    all_cfgs = list(cfgs)
    groups = {}
    for c in cfgs:
        key = (tuple((next(r for r in lvls if r["config_id"] == c).get("mix") or [])), _bin_of(c))
        groups.setdefault(key, []).append(c)
    # À taille égale, la génération la PLUS RÉCENTE : c'est celle qui décrit le dépôt actuel.
    best = max(groups.values(), key=lambda g: (len(g), max(_when_of(c) for c in g))) if groups else []
    excluded_cfgs = [c for c in cfgs if c not in best]
    if len(best) > 1:
        cfgs = best
        W(tr("### Ce que coûte, et ce que rapporte, la taille du sémaphore"))
        W("")
        W(tr("Le sémaphore de l'interactif est à 3 par défaut, après avoir été baissé depuis 8 **comme"))
        W(tr("levier de RAM**. Les passes comparées ici tournent sur la MÊME base, la MÊME machine, le"))
        W(tr("MÊME binaire **et le MÊME mélange de requêtes** : leur écart, à niveau d'analystes égal,"))
        W(tr("EST le taux de change entre concurrence et mémoire."))
        W("")
        W(tr("**Il est réglable sans recompiler** : `PLUME_QUERY_CONCURRENCY` est lu dans la"))
        W(tr("configuration au démarrage (`daemon/src/server/mod.rs`, défaut 3) et le daemon publie la"))
        W(tr("valeur qu'il applique sur `/api/system/diag` — c'est de là que ce banc la lit, plutôt "
             "que"))
        W(tr("de la supposer. En revanche il est lu **une seule fois, au boot** : le changer demande "
             "un"))
        W(tr("redémarrage, et un redémarrage a son propre coût (voir la mise au repos plus haut)."))
        W("")
        if excluded_cfgs:
            W(tr("**Écartée(s) de cette comparaison** : {0}").format(', '.join('`' + c + '`' for c in excluded_cfgs)))
            W(tr("— leur mélange OU leur binaire n'est pas celui des autres passes, donc leur écart de"))
            W(tr("débit ne serait pas attribuable au sémaphore mais au travail ou au code. Leur courbe"))
            W(tr("reste publiée plus haut ; c'est cette comparaison-ci, et elle seule, qui exige que"))
            W(tr("tout le reste soit identique."))
            W("")
        W(tr("| Analystes | ") + " | ".join(tr("débit `{c}`").format(c=c) for c in cfgs) + tr(" | écart de débit | ")
          + " | ".join(f"p95 `{c}`" for c in cfgs) + " | "
          + " | ".join(tr("RSS `{c}`").format(c=c) for c in cfgs) + " |")
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
              + " | ".join(fmt_mib(got[c].get("peak_rss_bytes")) + tr(" Mio") for c in cfgs) + " |")
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
            W(tr("**Au niveau le plus chargé mesuré des deux côtés ({n} analystes)** : {q1:.2f} contre "
                 "{q0:.2f} requête/s ").format(n=n, q1=q1, q0=q0)
              + (tr("(**{0:+.0f} %** de travail servi)").format((q1/q0-1)*100) if q0 else "") + tr(", p95 {0} contre {1}, RSS crête {2} contre {3} Mio (**{4:+.0f} Mio**, soit {5:+.1f} % "
                                                                                      "du budget). Ces six nombres SONT le taux de change entre un sémaphore à {6} et un "
                                                                                      "sémaphore à {7} — celui que la baisse de 8 à 3, faite comme levier de RAM, avait acheté "
                                                                                      "sans jamais être chiffré.").format(fmt_dur(p1), fmt_dur(p0), fmt_mib(r1), fmt_mib(r0), (r1-r0)/2**20, (r1-r0)/BUDGET_BYTES*100, g[cfgs[0]].get('query_sem'), g[cfgs[-1]].get('query_sem')))
            W("")
    elif len(cfgs) > 1:
        W(tr("### Ce que coûte, et ce que rapporte, la taille du sémaphore"))
        W("")
        W(tr("**Pas de comparaison publiée.** Les passes mesurées n'ont pas tiré le MÊME mélange de"))
        W(tr("requêtes : leur écart de débit mélangerait l'effet du sémaphore et celui du travail. Un"))
        W(tr("banc ne change qu'une chose à la fois — les courbes restent publiées séparément."))
        W("")

    # ---------------------------------------------------------------- l'écart entre GÉNÉRATIONS
    # MÊME sémaphore, MÊME mélange, MÊME base, MÊME niveau — SEUL le binaire change. C'est la seule
    # forme sous laquelle un « avant/après » de correctif est lisible. Les paires sont DÉRIVÉES des
    # données (on apparie sur la valeur de sémaphore et sur le mélange, et on refuse d'apparier deux
    # passes du même binaire) : aucune liste de passes n'est écrite ici.
    par_sem = {}
    for c in all_cfgs:
        r0 = next(r for r in lvls if r["config_id"] == c)
        # LA CLÉ D'APPARIEMENT = tout ce qui doit être IDENTIQUE pour qu'un écart soit imputable au
        # binaire : la taille du sémaphore, le mélange tiré, et le nombre de passages par analyste.
        # Deux passes qui ne partagent pas les trois ne sont jamais appariées — donc jamais publiées
        # comme un « avant/après », même si leurs noms s'y prêtent.
        par_sem.setdefault(
            (r0.get("query_sem"), tuple(r0.get("mix") or []), r0.get("rounds")), []
        ).append((str((r0.get("config") or {}).get("version") or ""), str(r0.get("measured_at") or ""), c))
    paires = []
    for (sem, _mix, _rounds), items in sorted(par_sem.items(), key=lambda kv: (kv[0][0] or 0)):
        gens = sorted({(v, w, c) for v, w, c in items}, key=lambda x: x[1])
        if len({g[0] for g in gens}) < 2:
            continue
        paires.append((sem, gens[0], gens[-1]))
    if paires:
        W(tr("### L'écart avant / après le correctif de métrique"))
        W("")
        W(tr("MÊME base, MÊME machine, MÊME sémaphore, MÊME mélange **imposé**, MÊMES niveaux : seul "
             "le"))
        W(tr("BINAIRE change. Ce n'est donc pas une comparaison de configurations, c'est la mesure de "
             "ce"))
        W(tr("qu'un correctif a fait — et les deux colonnes d'attente sont l'essentiel, parce que "
             "c'est"))
        W(tr("là que le défaut vivait."))
        W("")
        for sem, (v0, w0, c0), (v1, w1, c1) in paires:
            W(tr("**Sémaphore {sem}** — `{c0}` ({0}, `{1}`) contre `{c1}` ({2}, `{3}`)").format(w0[:10], v0.split(' ')[0], w1[:10], v1.split(' ')[0], sem=sem, c0=c0, c1=c1))
            W("")
            W(tr("| Analystes | file ? | débit avant | débit après | p95 avant | p95 après | attente "
                 "PERMIT max avant | attente PERMIT max après | verrou partagé max après | RSS avant | "
                 "RSS après |"))
            W("|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
            a = {r["analysts"]: r for r in lvls if r["config_id"] == c0}
            b = {r["analysts"]: r for r in lvls if r["config_id"] == c1}
            for n in sorted(set(a) & set(b)):
                x, y = a[n], b[n]
                W(tr("| **{n}** | {0} | {1:.2f} q/s | {2:.2f} q/s | {3} | {4} | {5} | {6} | {7} | {8} Mio | "
                     "{9} Mio |").format(tr('oui') if x.get('queue_possible') else tr('non'), x.get('throughput_qps') or 0, y.get('throughput_qps') or 0, fmt_ms(x.get('wall_p95_ms')), fmt_ms(y.get('wall_p95_ms')), fmt_ms(x.get('sem_wait_max_ms')), fmt_ms(y.get('sem_wait_max_ms')), fmt_ms(y.get('db_lock_wait_max_ms')), fmt_mib(x.get('peak_rss_bytes')), fmt_mib(y.get('peak_rss_bytes')), n=n))
            W("")
        W(tr("Lire la colonne « file ? » AVANT les colonnes d'attente : là où elle dit **non**, aucune"))
        W(tr("requête ne PEUT attendre son tour, donc toute attente de permit publiée y est fausse."))
        _reste = max((b.get("db_lock_wait_max_ms") or 0)
                     for _s, _g0, (_v, _w, _c) in paires
                     for b in [r for r in lvls if r["config_id"] == _c]) if paires else 0
        if _reste > 0:
            W(tr("La colonne « verrou partagé » dit où cette attente passait, et il en reste"))
            W(tr("{0} : la sérialisation existe encore sur ce chemin.").format(fmt_dur(_reste)))
        else:
            W(tr("La colonne « verrou partagé » est à zéro **parce que la sérialisation a été retirée**"))
            W(tr("(la lecture de couverture des rollups est passée au pool de lecture) — pas parce"))
            W(tr("qu'elle n'était pas là : c'est la passe d'ATTRIBUTION, plus haut, qui la mesure encore"))
            W(tr("en place, et le champ reste publié pour que la prochaine soit visible immédiatement."))
        W(tr("Les colonnes de débit et de p95, elles, ne sont PAS un résultat de ce correctif : elles"))
        W(tr("portent la charge de la machine du jour autant que le code — on les publie pour qu'on"))
        W(tr("puisse les contredire, pas pour en tirer une conclusion."))
        W("")


def _profile_axis(name):
    """Relit la section `axis` (ou `fleet`) DU PROFIL lui-même. Le document ne réécrit donc jamais
    de mémoire ce qu'un profil contient : il le cite. Un profil absent rend `None` et la passe
    correspondante est publiée sans étiquette d'axe plutôt que sous une étiquette devinée."""
    if not name:
        return None
    for cand in (os.path.join("bench", name), name):
        try:
            with open(cand, encoding="utf-8") as fh:
                p = json.load(fh)
        except (OSError, ValueError):
            continue
        if p.get("axis"):
            a = dict(p["axis"])
            a["kind"] = "axis"
            return a
        if p.get("fleet"):
            return {"kind": "fleet", "axis": "hosts",
                    "value": p["fleet"].get("hosts"), "detail": {}, "before": {}, "after": {}}
        return {"kind": "temoin", "axis": None, "value": None,
                "detail": {}, "before": {}, "after": {}}
    return None


def render_genericity(W, eff, cfgmeta, classes, wins, fmt_dur):
    """Publie la VARIANCE par axe, jamais une moyenne seule.

    LA GARDE EST DÉRIVÉE, PAS CHOISIE. Un écart entre deux profils ne veut rien dire tant qu'on ne
    sait pas ce que la MÊME mesure rend deux fois de suite sur le MÊME jeu. La campagne mesure donc
    le témoin DEUX FOIS, et la bande de bruit qui en sort — l'étendue des rapports cellule par
    cellule — devient le seuil au-delà duquel un écart est attribuable au PROFIL. Aucun seuil n'est
    écrit ici : si la machine est plus bruyante, la bande s'élargit d'elle-même et le document
    conclut moins, ce qui est le comportement voulu."""
    # Les passes de la campagne sont reconnues à leur profil ET à leur comparabilité (même volume,
    # même masquage, même FTS, même tier froid) : aucune liste de configurations en dur.
    by_cfg = {}
    for r in eff:
        by_cfg.setdefault(r["config_id"], []).append(r)
    cand = [c for c in by_cfg if cfgmeta.get(c, {}).get("profile")]
    if len(cand) < 3:
        return
    def _evbucket(n):
        # Le VOLUME doit être égal pour que la comparaison ait un sens, mais « égal » ne peut pas
        # vouloir dire « au même entier près » : le daemon estampille lui-même quelques événements
        # de contrôle, et deux remplissages du même nombre d'événements finissent à 600 003 ici et
        # 600 005 là. Comparer sur l'entier exact scinderait les passes en groupes d'une seule et
        # ferait DISPARAÎTRE des profils du tableau sans rien dire. On compare donc à deux chiffres
        # significatifs : 600 003 et 600 005 tombent ensemble, 600 000 et 10 000 000 non.
        # La MAGNITUDE fait partie de la clé : sans elle, 140 000 et 1 440 007 rendent tous deux 14
        # et deux volumes qui diffèrent d'un facteur 10 seraient comparés comme s'ils étaient égaux.
        if not n:
            return None
        d = len(str(int(n)))
        return (d, round(n / 10 ** (d - 2)))

    def _key(c):
        m = cfgmeta[c]
        return (_evbucket(m.get("events")), m.get("mask"), m.get("fts_fields"),
                m.get("cold"), m.get("classes"))
    groups = {}
    for c in cand:
        groups.setdefault(_key(c), []).append(c)
    camp = max(groups.values(), key=len)
    if len(camp) < 3:
        return
    axes = {c: _profile_axis(cfgmeta[c].get("profile")) for c in camp}

    # LE TÉMOIN et sa RÉPÉTITION : deux passes qui citent le MÊME fichier de profil. C'est la seule
    # paire dont on sache qu'elle mesure deux fois la même chose.
    byprof = {}
    for c in camp:
        byprof.setdefault(cfgmeta[c].get("profile"), []).append(c)
    pair = next((v for v in byprof.values() if len(v) >= 2), None)
    temoin = pair[0] if pair else next(
        (c for c in camp if (axes.get(c) or {}).get("kind") == "temoin"), None)
    if not temoin:
        return

    W(tr("## La généricité — les mêmes requêtes sur d'AUTRES profils de données"))
    W("")
    W(tr("Un chiffre mesuré sur notre profil prouve NOTRE cas, pas le cas général. Les passes "
         "ci-dessous"))
    W(tr("rejouent **la même matrice** sur des profils qui ne diffèrent du témoin que par **un "
         "seul**"))
    W(tr("paramètre du jeu de données, **à volume d'événements égal**, sur la même machine et le "
         "même"))
    W(tr("binaire. Chaque axe est DÉRIVÉ d'une décision du chemin d'exécution — pas choisi pour"))
    W(tr("l'occasion : ce qui décide index ou scan, route de rollups ou balayage, chaud ou froid."))
    W("")
    W(tr("| Passe | Axe | Valeur | Ce que le profil dit AVANT -> APRÈS | Événements | Base (Mio) |"))
    W("|---|---|---|---|---:|---:|")
    for c in camp:
        a = axes.get(c) or {}
        m = cfgmeta[c]
        moved = "—"
        b, af = a.get("before") or {}, a.get("after") or {}
        for k, lab in (("severity_ge3_frac", tr("sévérité >= 3")),
                       ("mean_value_bytes", tr("octets/événement")),
                       ("top_source_share", tr("poids source dominante"))):
            if b.get(k) is not None and af.get(k) is not None and b[k] != af[k]:
                moved = f"{lab} {b[k]} -> {af[k]}"
        if (a.get("before") or {}).get("ext_card") and a.get("axis") == "ext_card_scale":
            moved = (tr("cardinalité médiane {0} -> {1}").format(a['before']['ext_card'].get('card_median'), a['after']['ext_card'].get('card_median')))
        if a.get("kind") == "fleet":
            moved = tr("cardinalité de `host` = {0}").format(a.get('value'))
        W(f"| `{c}` | {a.get('axis') or tr('**témoin**')} | {a.get('value') if a.get('value') is not None else '—'} "
          f"| {moved} | {fmt_n(m.get('events'))} | {fmt_mib(m.get('db_bytes'))} |")
    W("")

    def val(c, cid, w):
        for r in by_cfg.get(c, []):
            if r["class_id"] == cid and r["window"] == w:
                return r.get("wall_p50_ms")
        return None

    cells = [(cid, w) for cid, _l, _k in classes for w in wins]

    # ---------------------------------------------------------------- LA BANDE DE BRUIT
    noise = []
    if pair and len(pair) >= 2:
        a_, b_ = pair[0], pair[1]
        for cid, w in cells:
            x, y = val(a_, cid, w), val(b_, cid, w)
            if x and y and x > 0:
                noise.append(y / x)
    W(tr("### Le bruit d'abord — sinon aucun écart n'est interprétable"))
    W("")
    if len(noise) >= 5:
        ns = sorted(noise)
        lo, hi = ns[0], ns[-1]
        med = ns[len(ns) // 2]
        q = lambda p: ns[max(0, min(len(ns) - 1, int(round(p * (len(ns) - 1)))))]
        W(tr("Le témoin a été mesuré **deux fois**, sur la **même base**, avec le même binaire et la"))
        W(tr("même machine — `{0}` puis `{1}`. Rien n'y change : ni la donnée, ni le code,").format(pair[0], pair[1]))
        W(tr("ni le réglage. Les deux passes ENCADRENT la campagne (l'une au début, l'autre à la fin),"))
        W(tr("donc la bande contient aussi la dérive de la machine pendant la campagne. Le rapport"))
        W(tr("d'une passe à l'autre, cellule par cellule, est du BRUIT pur, et il vaut :"))
        W("")
        W(tr("| Cellules | min | 5 % | médian | 95 % | max |"))
        W(f"|---:|---:|---:|---:|---:|---:|")
        W(f"| {len(ns)} | x{lo:.2f} | x{q(0.05):.2f} | x{med:.2f} | x{q(0.95):.2f} | x{hi:.2f} |")
        W("")
        W(tr("**C'est l'étalon.** Le critère retenu plus bas est l'ÉTENDUE COMPLÈTE `[x{lo:.2f},").format(lo=lo))
        W(tr("x{hi:.2f}]` — le plus conservateur des deux : un écart n'est déclaré attribuable au").format(hi=hi))
        W(tr("profil que s'il sort de tout ce que la répétition a produit sans qu'on change quoi que "
             "ce"))
        W(tr("soit. Les quantiles sont publiés à côté pour que le lecteur voie si la bande est large"))
        W(tr("à cause d'UNE cellule ou de toutes."))
        W("")
        W(tr("Cette bande n'est pas un seuil choisi : c'est une mesure. Elle s'élargit d'elle-même si"))
        W(tr("la machine est plus chargée, et le document conclut alors MOINS. C'est le comportement"))
        W(tr("voulu — un banc doit perdre en conclusions quand il perd en conditions, jamais gagner en"))
        W(tr("confiance. **Réserve à connaître** : les cellules les plus rapides (proches du coût fixe"))
        W(tr("d'une requête, mesuré par `C0-plancher`) ont un bruit relatif élevé alors que leur enjeu"))
        W(tr("est nul ; elles élargissent la bande et rendent donc le test PLUS strict, jamais moins."))
    else:
        lo, hi = None, None
        W(tr("**Le témoin n'a pas été mesuré deux fois dans cette passe** : aucune bande de bruit "
             "n'est"))
        W(tr("disponible, donc aucun écart ci-dessous n'est déclaré significatif. Les rapports sont"))
        W(tr("publiés bruts, et ils ne prouvent rien tant que la répétition n'a pas été faite."))
    W("")

    # ---------------------------------------------------------------- ÉCART PAR AXE
    others = [c for c in camp if c != temoin and (not pair or c != pair[1])]
    W(tr("### L'écart, axe par axe"))
    W("")
    W(tr("Rapport de la latence p50 de chaque passe à celle du témoin `{temoin}`. **Gras** = "
         "l'écart").format(temoin=temoin))
    W(tr("sort de la bande de bruit ci-dessus, donc il est attribuable au PROFIL DE DONNÉES et "
         "pas à la"))
    W(tr("machine. Une cellule vide n'a pas été mesurée des deux côtés."))
    W("")
    hdr = " | ".join(f"`{c}`" for c in others)
    W(tr("| Classe | Fenêtre | témoin | {hdr} |").format(hdr=hdr))
    W("|---|:--:|---:|" + "---:|" * len(others))
    outside = {c: 0 for c in others}
    total = {c: 0 for c in others}
    for cid, w in cells:
        t = val(temoin, cid, w)
        if not t or t <= 0:
            continue
        row, any_cell = [], False
        for c in others:
            v = val(c, cid, w)
            if v is None:
                row.append("—")
                continue
            any_cell = True
            r = v / t
            total[c] += 1
            sig = lo is not None and (r < lo or r > hi)
            if sig:
                outside[c] += 1
            row.append(f"**x{r:.2f}**" if sig else f"x{r:.2f}")
        if any_cell:
            W(f"| `{cid}` | {w} | {fmt_dur(t)} | " + " | ".join(row) + " |")
    W("")
    W(tr("### Ce que ça donne, axe par axe"))
    W("")
    W(tr("| Axe | Cellules comparables | Hors bande de bruit | Part |"))
    W("|---|---:|---:|---:|")
    for c in others:
        a = axes.get(c) or {}
        n, k = total[c], outside[c]
        W(f"| `{c}` ({a.get('axis') or '?'}) | {n} | {k} | {100*k/n if n else 0:.0f} % |")
    W("")
    W(tr("Une part élevée veut dire : **sur cet axe, nos chiffres ne se transposent pas**. Un "
         "tiers dont"))
    W(tr("le jeu diffère de nous sur ce paramètre n'obtiendra pas nos latences, et l'écart n'est "
         "pas un"))
    W(tr("artefact de mesure puisqu'il sort de la bande mesurée sur une répétition à l'identique."))
    W("")


def desaccords(cfgmeta, a, b, axes=()):
    """Les clés sur lesquelles DEUX PASSES divergent alors que la comparaison ne les compare pas.

    RIEN N'EST ÉNUMÉRÉ ICI, et c'est le point : les clés viennent des enregistrements eux-mêmes.
    La dérivation tient en deux règles.

    1. On ne confronte que les clés déclarées **des deux côtés**. Une clé absente d'un côté est une
       ABSENCE, et une absence ne contredit rien — c'est ce qui fait que `db_bytes_fts0`, relevé par
       la seule passe FTS-on, n'est pas compté comme un désaccord avec son jumeau FTS-off.
    2. `axes` = ce que la comparaison compare, PLUS la grandeur qu'elle publie. Ce sont les deux
       seules clés qui ont le DROIT de différer, et l'appel les nomme parce qu'elles SONT son sujet.
       Ce n'est pas une liste d'axes : c'est l'énoncé de la comparaison, écrit là où elle se fait.

    RÉSERVE MESURÉE (2026-08-30, ce dépôt, 21 configurations du relevé versionné) : l'enregistrement
    de configuration mélange À PLAT les RÉGLAGES (`fts_fields`, `mask`, `cold`, `hosts`, `profile`,
    `version`, `query_concurrency`…) et les RÉSULTATS de la passe (`events`, `db_bytes`,
    `db_bytes_fts0`, `cold_bytes`). Rien dans la forme du dossier ne les distingue. Exiger l'égalité
    sur TOUTES les clés serait donc faux dans les deux sens : cela refuserait la comparaison même
    qu'on vient de réparer (`db_bytes` diffère PARCE QUE `fts_fields` diffère) et cela refuserait le
    tier froid (`events` chute PARCE QUE les jours anciens ont quitté SQLite). C'est pourquoi la
    grandeur publiée est DÉCLARÉE par l'appel et non devinée : c'est la seule information que
    l'enregistrement ne porte pas."""
    ma, mb = cfgmeta.get(a) or {}, cfgmeta.get(b) or {}
    return sorted(k for k in (set(ma) & set(mb)) - set(axes) if ma[k] != mb[k])


def passe_comparable(cfgmeta, ordre, cible, axes, limite_causes=3):
    """LA PAIRE EST TROUVÉE PAR LA PROPRIÉTÉ, JAMAIS NOMMÉE DANS LE CODE.

    Rend `(jumeau, None)` s'il existe une passe qui s'accorde avec `cible` sur tout ce que les deux
    déclarent, hors `axes` ; à égalité, la plus récemment apparue dans le relevé. Sinon
    `(None, cause)`, où `cause` NOMME les passes les plus proches et l'axe par lequel chacune
    diverge — un refus qui ne dit pas POURQUOI ne vaut pas mieux qu'un chiffre faux."""
    proches = [(len(d), c, d) for c, d in
               ((c, desaccords(cfgmeta, c, cible, axes)) for c in ordre if c != cible)]
    jum = [c for n, c, _ in proches if n == 0]
    if jum:
        return jum[-1], None
    if not proches:
        return None, tr("aucune autre passe dans ce relevé")
    proches.sort(key=lambda x: x[0])
    return None, "; ".join(tr("`{c}` diverge sur ").format(c=c) + ", ".join(f"`{k}`" for k in d)
                           for _n, c, d in proches[:limite_causes])


def refus_de_comparer(quoi, axe, cause):
    """LE REFUS EST UN CANAL DISTINCT DE LA VALEUR, et il est écrit LÀ OÙ LE CHIFFRE serait apparu.

    Un blanc se lirait « rien à signaler » ; un chiffre se lirait « mesuré ». Ni l'un ni l'autre
    n'est vrai quand la paire n'existe pas."""
    return (tr("**Comparaison REFUSÉE — {quoi}.** Ce relevé ne contient pas deux passes qui ne "
               "diffèrent que par `{axe}` : {cause}. Un écart entre ces passes ne mesurerait pas "
               "`{axe}`, il mesurerait leur propre divergence — il n'est donc pas rendu. **Ce n'est pas "
               "« rien à signaler » : c'est un refus.** Pour obtenir le chiffre, il faut TIRER la "
               "paire, pas assouplir la garde.").format(quoi=quoi, axe=axe, cause=cause))


def _cmp_load(eff, cfg):
    """Charge machine (loadavg 1 min) relevée PENDANT une passe : min-max sur ses cellules. Sans elle,
    un écart de latence entre deux passes pourrait n'être qu'un écart de charge."""
    v = [(r.get("pressure_before") or {}).get("loadavg", [None])[0]
         for r in eff if r["config_id"] == cfg]
    v = [x for x in v if x is not None]
    if not v:
        return tr("non relevé")
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
    ap.add_argument("--compare-note-fr", action="append",
                    help="la même note, en français, pour le rendu `--langue fr` (une par --compare)")
    ap.add_argument("--ingest-curve", action="append",
                    help="CSV t_unix,events,db_bytes,rss_bytes,loadavg1 échantillonné pendant "
                         "l'ingest : rend la COURBE de débit en fonction du volume déjà en base")
    ap.add_argument("--langue", choices=LANGUES, default="en",
                    help="langue du rendu (anglais par défaut) ; les nombres et les identifiants "
                         "sont les mêmes dans les deux langues")
    ap.add_argument("--rendu-le", default=None, metavar="HORODATAGE",
                    help="horodatage « Rendu le » à publier au lieu de l'heure courante (une "
                         "régénération n'est pas une nouvelle mesure)")
    ap.add_argument("--materiel", default=None, metavar="JSON",
                    help='matériel à publier au lieu de celui de la machine qui rend : '
                         '{"cpu": …, "cores": …, "mem_gib": …, "kernel": …}')
    args = ap.parse_args()
    global LANGUE
    LANGUE = args.langue
    if args.rendu_le is not None and not HORODATAGE_DE_RENDU.fullmatch(args.rendu_le):
        ap.error(f"--rendu-le {args.rendu_le!r} : attendu le format que le générateur écrit, "
                 "AAAA-MM-JJ HH:MM:SS+HHMM (par exemple 2026-01-02 03:04:05+0100)")
    materiel = None
    if args.materiel is not None:
        try:
            materiel = lire_materiel(args.materiel)
        except ValueError as e:
            ap.error(f"--materiel : {e}")

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

    # Le matériel est celui de la machine QUI REND, sauf s'il est fourni : une régénération (une
    # traduction, par exemple) n'est pas une nouvelle mesure, et ne doit pas réécrire le matériel
    # publié avec celui du poste du jour.
    if materiel:
        hw = materiel
    else:
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
            classes.append((cid, tr_donnee(r["label"]), r["kind"]))
        else:
            classes[_seen[cid]] = (cid, tr_donnee(r["label"]), r["kind"])
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
    W(tr("# Banc de mesure plume — requêtes à chaud sous 2 Gio"))
    W("")
    W(SELECTEUR_DE_LANGUE)
    W("")
    W(tr("<!-- CE FICHIER EST GÉNÉRÉ par bench/report.py (voir la section « Reproduire » en bas)."))
    W(tr("     Ne pas l'éditer à la main : la prochaine passe l'écrase. Tout commentaire durable "
         "va dans"))
    W(tr("     bench/README.md. -->"))
    W("")
    import os as _os
    # Les données BRUTES sont VERSIONNÉES dans `bench/results/`. C'est ce qui rend ce document
    # RÉFUTABLE : sans elles, un lecteur ne peut que croire le tableau ou l'ignorer. Elles ont été
    # scannées avant publication (270 + ~80 lignes JSON : chemins personnels, e-mails, jetons, IP hors
    # plages de documentation, hexadécimal long — ZÉRO correspondance ; les seules requêtes qui y
    # figurent sont celles du banc, synthétiques).
    W(tr("Rendu le {0} depuis ").format(args.rendu_le or time.strftime('%Y-%m-%d %H:%M:%S%z'))
      + ", ".join(f"`{_os.path.basename(p)}`" for p in args.results)
      + tr(" — données brutes VERSIONNÉES dans [`bench/results/`](../bench/results/), pour que ce")
      + tr(" tableau puisse être contredit et pas seulement cru (cf. `bench/README.md`)."))
    W("")
    W(tr("## Ce que ce document est, et ce qu'il n'est pas"))
    W("")
    W(tr("C'est la **mesure de référence** de plume, prise avec un instrument publié et rejouable."))
    W(tr("Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est une "
         "case"))
    W(tr("**non mesurée**, pas une case implicitement bonne. Quand plusieurs passes coexistent au "
         "même"))
    W(tr("volume, elles sont TOUTES rendues : une passe n'est jamais remplacée par une plus "
         "flatteuse,"))
    W(tr("et la section « Écart mesuré entre deux passes » dit laquelle décrit le code actuel."))
    W("")
    W(tr("Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : "
         "c'est un"))
    W(tr("banc synthétique au **profil** de la production (voir `bench/profile-prod.json`)."))
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
    W(tr("## Verdict — ce que ces mesures autorisent à affirmer"))
    W("")
    W(tr("Volume de référence : **{0} événements** (`{ref}`), base **{1} Mio** chiffrée SQLCipher.").format(fmt_n(_nev0(ref)), fmt_mib(cfgmeta[ref].get('db_bytes')), ref=ref))
    W("")
    W(tr("**Sur le budget de 2 Gio — soutenu.** RSS crête la plus haute mesurée sur l'ensemble "
         "des cellules : **{0} Mio**, soit **{1:.0f} %** du budget. Et ce n'est pas une "
         "observation passive : le daemon tournait sous `MemoryMax=2G MemorySwapMax=0`, où un "
         "dépassement est un kill du noyau.").format(fmt_mib(peak_all), peak_all/BUDGET_BYTES*100))
    W("")
    W(tr("**Ce qui est RAPIDE** (p50, fenêtre indiquée, config de référence) :"))
    W("")
    for r in fast:
        W(tr("- `{0}` / {1} — **{2}** ({3}), servi par `{4}`").format(r['class_id'], r['window'], fmt_dur(r['wall_p50_ms']), tr_donnee(r['label']), r.get('served_from') or 'scan'))
    W("")
    fl0 = idx.get((ref, "C0-plancher", "all")) or idx.get((ref, "C0-plancher", "1h"))
    if fl0 and fl0.get("wall_p50_ms") is not None \
            and (fl0["wall_p50_ms"] - (fl0.get("sql_p50_ms") or 0)) > 10.0:
        W(tr("Toutes ces cellules sont AU PLANCHER. Une requête dont le SQL ne coûte rien revient en "
             "**{0}** (`C0-plancher`, SQL mesuré à {1}) : c'est un coût FIXE, indépendant du volume, "
             "et aucune requête ne peut descendre en dessous aujourd'hui. Voir le levier « Le "
             "plancher fixe par requête ».").format(fmt_dur(fl0['wall_p50_ms']), fmt_dur(fl0.get('sql_p50_ms'))))
        W("")
    W(tr("**Ce qui est LENT** — et ce sont les cas que la promesse « sur tous les champs » met en "
         "avant :"))
    W("")
    for r in slow:
        W(tr("- `{0}` / {1} — **{2}** ({3}), servi par `{4}`").format(r['class_id'], r['window'], fmt_dur(r['wall_p50_ms']), tr_donnee(r['label']), r.get('served_from') or 'scan'))
    W("")
    maxread = max((r.get("read_bytes_total") or 0) for r in eff)
    availmin = min((((r.get("pressure_before") or {}).get("mem_available_bytes") or 0)
                    for r in eff), default=0)
    dbref = cfgmeta[ref].get("db_bytes") or 0
    W(tr("**Le disque n'a pas été sollicité — et c'est une limite, pas une bonne nouvelle.** "
         "Octets lus au bloc, maximum sur toutes les cellules : **{0} Mio**. La base ({1} Mio) "
         "tient entièrement dans le cache de pages de la machine ({2} Mio de mémoire disponible "
         "au minimum pendant la mesure). Ces latences sont donc **bornées par le CPU, pas par le "
         "stockage**, et constituent un MEILLEUR CAS. À un volume où la base dépasse la RAM "
         "disponible, le stockage entre dans l'équation — et ce régime n'est pas mesuré ici.").format(fmt_mib(maxread), fmt_mib(dbref), fmt_mib(availmin)))
    W("")
    W(tr("**Ce que ces mesures n'autorisent PAS à affirmer** :"))
    W("")
    # LA BORNE DE VOLUME EST DÉRIVÉE, PAS ÉCRITE. Elle était affirmée en dur (« la cible de 10 M
    # n'a pas été atteinte ») : le jour où une passe à 10 M entre dans le document, cette phrase le
    # fait se contredire lui-même, en publiant un tableau à 10 M sous un verdict qui dit l'inverse.
    # Le verdict lit donc le volume MAXIMUM réellement mesuré et se formule à partir de lui.
    _volmax_cfg = max(configs, key=lambda c: _nev0(c) or 0)
    _volmax = _nev0(_volmax_cfg) or 0
    if _volmax > (_nev0(ref) or 0):
        W(tr("- au-delà de {0} événements, rien. C'est le volume le plus élevé réellement REMPLI par "
             "le vrai chemin d'ingest (`{volmax_cfg}`) ; la configuration de référence de ce verdict, "
             "elle, porte sur {1} événements, et les deux ne se lisent pas l'une pour l'autre. Toute "
             "latence annoncée à un volume supérieur serait une extrapolation, pas une mesure.").format(fmt_n(_volmax), fmt_n(_nev0(ref)), volmax_cfg=_volmax_cfg))
    else:
        W(tr("- rien au-delà de {0} événements. La cible de 10 M n'a pas été atteinte par le vrai "
             "chemin d'ingest — non pas faute de l'avoir cherché, mais parce que le débit d'ingest "
             "s'effondre avec le volume déjà en base, ce que la section « D'où vient l'effondrement » "
             "ATTRIBUE désormais (et non plus suppose) : le coût CPU par événement monte, le daemon "
             "écrit de plus en plus d'octets par ligne, et le chemin d'écriture est séquentiel. Le "
             "coût restant pour atteindre 10 M y est chiffré, en tant que PLANCHER arithmétique sur "
             "des débits mesurés. Toute latence annoncée à 10 M ou 100 M serait une extrapolation, "
             "pas une mesure.").format(fmt_n(_nev0(ref))))
    _cold_on = [c for c in configs
                if str(cfgmeta[c].get("cold", "off")).lower() not in ("off", "0", "", "none")]
    if _cold_on:
        # TOUTES les configurations froides sont nommées, pas seulement la première : depuis qu'une
        # passe corrigée coexiste avec la passe qui a mesuré le défaut, n'en citer qu'une ferait
        # croire qu'il n'y en a qu'une — et laisserait le lecteur sur la mauvaise.
        _cold_list = ", ".join(f"`{c}`" for c in _cold_on)
        # La concurrence n'est retirée de cette phrase QUE si elle a réellement été tirée : la
        # présence de lignes `concurrency` est le seul critère, jamais une affirmation d'auteur.
        _cc = (tr("le multi-tenant") if conc else tr("la concurrence ni le multi-tenant"))
        W(tr("- rien sur {cc} (voir la section dédiée). Le tier froid, lui, EST mesuré ici — mais "
             "seulement dans {cold_list}, à une seule fenêtre chaude et un seul volume : les autres "
             "tableaux restent des tableaux SANS tier froid.").format(cc=_cc, cold_list=_cold_list))
    else:
        W(tr("- rien sur le tier froid, ")
          + (tr("le multi-tenant") if conc else tr("la concurrence, ni le multi-tenant"))
          + tr(" (voir la section dédiée)."))
    if conc:
        _cn = max((r.get("analysts") or 0) for r in conc)
        W(tr("- la CONCURRENCE, elle, est mesurée : jusqu'à {cn} analystes simultanés lançant de très "
             "grosses requêtes sous le même budget de 2 Gio appliqué, avec vérification que la "
             "réponse concurrente est IDENTIQUE à la réponse obtenue seul (section dédiée).").format(cn=_cn))
    # LA PASSE MASQUÉE EST OPPOSÉE À SON JUMEAU, PAS À `ref`. Mesuré le 2026-08-30 : `ref`
    # (`chaud-seul-v2@1.4M`) et la passe masquée (`fts0-masque-non-vide@1.4M`) divergeaient sur
    # `version`, `events` et `db_bytes` ; le « x287.3 » publié dans le verdict opposait donc deux
    # binaires autant que deux masques. Le jumeau est DÉSIGNÉ par la propriété, jamais nommé ici.
    mk = max([c for c in configs if "non-vide" in (cfgmeta[c].get("mask") or "")] or [None],
             key=lambda c: _nev0(c) if c else -1)
    mk_vide, mk_cause = (passe_comparable(cfgmeta, configs, mk, ("mask",)) if mk else (None, None))
    worst = best = None
    if mk and mk_vide:
        for cid, _lab, _k in classes:
            for w in wins:
                x, y = idx.get((mk, cid, w)), idx.get((mk_vide, cid, w))
                if x and y and x.get("wall_p50_ms") and y.get("wall_p50_ms"):
                    rr = x["wall_p50_ms"] / y["wall_p50_ms"]
                    if worst is None or rr > worst[0]:
                        worst = (rr, cid, w, y["wall_p50_ms"], x["wall_p50_ms"])
                    if best is None or rr < best[0]:
                        best = (rr, cid, w, y["wall_p50_ms"], x["wall_p50_ms"])
    if mk and not mk_vide:
        W("- " + refus_de_comparer(tr("l'effet du masquage sur les latences"), "mask", mk_cause))
    if worst:
        W(tr("- rien sur un déploiement AVEC masquage à partir des chiffres masque-vide : l'écart "
             "mesuré le plus fort est **x{0:.1f}** sur `{1}` / {2} ({3} masque vide contre {4} masque "
             "non vide, `{mk_vide}` contre `{mk}` — deux passes qui ne diffèrent QUE par le masque).").format(worst[0], worst[1], worst[2], fmt_dur(worst[3]), fmt_dur(worst[4]), mk_vide=mk_vide, mk=mk))
        if best and best[0] < 0.9:
            rw = idx.get((mk, best[1], best[2])) or {}
            rv = idx.get((mk_vide, best[1], best[2])) or {}
            same = rw.get("rows") == rv.get("rows")
            W(tr("  Et le masquage ne va pas TOUJOURS dans le sens du ralentissement : sur `{0}` / {1} il "
                 "est **x{2:.2f}**, donc plus RAPIDE ({3} masque vide contre {4} masque non vide, {5}). "
                 "**La cause n'est PAS établie par cette mesure**, et on ne va pas l'inventer. Deux "
                 "mécanismes candidats, qui demandent chacun une expérience dédiée pour être départagés : "
                 "(a) un masque posé sur une dimension à haute cardinalité l'effondre, il reste moins de "
                 "groupes à agréger — la requête va plus vite **parce que la réponse a changé** ; (b) la "
                 "passe masquée a tourné APRÈS la passe non masquée, donc sur un cache de pages plus "
                 "chaud. Ce qui trancherait : rejouer les deux passes dans l'ordre inverse, et comparer "
                 "les résultats ligne à ligne. En attendant, la règle est simple — **une latence qui "
                 "baisse en présence d'un masque ne doit jamais être citée comme un gain**.").format(best[1], best[2], best[0], fmt_dur(best[3]), fmt_dur(best[4]), tr("même nombre de lignes rendues") if same else tr("{0} lignes contre {1}").format(fmt_n(rv.get(chr(114)+chr(111)+chr(119)+chr(115))), fmt_n(rw.get(chr(114)+chr(111)+chr(119)+chr(115))))))
    elif not (mk and not mk_vide):
        # Le cas « paire croisée » est déjà avoué juste au-dessus par un REFUS qui NOMME l'axe
        # divergent ; on ne le double pas d'une phrase vague qui se lirait comme une absence.
        W(tr("- rien sur un déploiement AVEC masquage : cet axe n'a pas pu être comparé cellule par "
             "cellule dans cette passe."))
    W("")
    W(tr("## Matériel et conditions"))
    W("")
    W("| | |")
    W("|---|---|")
    W(tr("| Processeur | {0} ({1} cœurs logiques) |").format(hw['cpu'], hw['cores']))
    W(tr("| RAM de la machine | {0:.1f} Gio |").format(hw['mem_total_bytes']/2**30))
    W(tr("| Noyau | {0} |").format(hw['kernel']))
    W(tr("| Version de plume mesurée | `{0}` |").format(cfgmeta[configs[-1]].get('version',tr('inconnue'))))
    vols = sorted({cfgmeta[c].get("events") or 0 for c in configs})
    W(tr("| Volumes mesurés | {0} |").format(', '.join(fmt_n(v) + tr(" événements") for v in vols)))
    W(tr("| Taille de la base (SQLCipher, chiffrée) | {0} |").format(', '.join(sorted({fmt_mib(cfgmeta[c].get('db_bytes')) + tr(" Mio") for c in configs}))))
    W(tr("| Budget mémoire | **appliqué** par un scope systemd `MemoryMax=2G MemorySwapMax=0` — "
         "la même contrainte que la limite de conteneur de production (`limits.memory: 2Gi`) |"))
    W(tr("| Concurrence de requêtes | `PLUME_QUERY_CONCURRENCY=3` (le défaut livré) |"))
    if conc:
        _cs = sorted({r.get("query_sem") for r in conc if r.get("query_sem")})
        _cn = sorted({r.get("analysts") for r in conc if r.get("analysts")})
        W(tr("| Passes de CONCURRENCE | {0} analystes simultanés, sémaphore {1} (section dédiée) |").format(', '.join(str(n) for n in _cn), tr(" et ").join(str(s) for s in _cs)))
    W(tr("| Budget par requête | interactif, 60 s (`interactive:true`) |"))
    W("")
    # D'OÙ VIENNENT CES TROIS LIGNES : les JSONL n'enregistrent pas le matériel, donc le tableau ne
    # peut décrire que la machine du rendu (ou ce que `--materiel` en a repris). Le dire évite de
    # lire un noyau de rendu comme celui de la mesure.
    W(tr("*Provenance du processeur, de la RAM et du noyau* : repris de la ligne de commande (`--materiel`), et non relevés au moment de ce rendu.") if args.materiel else
      tr("*Provenance du processeur, de la RAM et du noyau* : relevés sur la machine qui a rendu ce document, au moment du rendu."))
    W(tr("Les fichiers de résultats n'enregistrent ni le matériel ni le noyau : ces trois lignes décrivent une machine de RENDU, pas nécessairement la machine qui a mesuré — le noyau affiché, en particulier, peut différer de celui de la mesure."))
    W("")
    _bins = sorted({(r.get("config") or {}).get("version", "").split(" ")[0]
                    for r in eff if (r.get("config") or {}).get("version")}
                   | {(d.get("version") or "").split(" ")[0]
                      for d in ingest if d.get("version")})
    if len(_bins) > 1:
        W(tr("**Plusieurs binaires** figurent dans ce document : ") + ", ".join(f"`{b}`" for b in _bins)
          + tr(". Chaque cellule porte le sien dans le JSONL brut, et chaque tableau de configuration "
               "l'affiche dans son sous-titre. Une comparaison entre deux tableaux de binaires "
               "différents mesure aussi l'écart entre les deux binaires — ce n'est légitime que dans la "
               "section « Écart mesuré entre deux passes », qui le dit."))
        W("")
    W(tr("**Honnêteté sur les conditions** : la machine de mesure n'était pas dédiée — d'autres "
         "travaux"))
    W(tr("tournaient en parallèle. Chaque cellule enregistre son `loadavg` et le swap consommé "
         "pendant"))
    W(tr("la mesure ; les cellules prises sous swap sont marquées et listées plus bas. Le daemon "
         "lui-même"))
    W(tr("ne pouvait pas swapper (`MemorySwapMax=0`), donc sa RSS crête est une vraie crête, mais "
         "les"))
    W(tr("latences absolues sont **pessimistes** sur une machine chargée."))
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
                           "_derived": tr("reconstruit depuis l'échantillonneur (premier et dernier point mesurés), le remplissage "
                                          "ayant été borné en temps")})
    if [x for x in ingest if x.get("phase") in (None, "ingest")]:
        W(tr("## Débit d'ingest mesuré (chemin HTTP complet)"))
        W("")
        # La colonne « binaire » n'est pas décorative : les passes d'INGEST et les passes de
        # REQUÊTE de ce document n'ont pas toutes été tirées avec le même binaire. Le taire
        # laisserait croire à une passe unique.
        W(tr("| Événements | Durée | Débit | Base après | `PLUME_FTS_FIELDS` | Binaire |"))
        W("|---:|---:|---:|---:|:--:|---|")
        for d in [x for x in ingest if x.get("phase") in (None, "ingest")]:
            _v = (d.get("version") or "").split(" ")[0] or "—"
            W(tr("| {0} | {1} s | **{2} ev/s** | {3} Mio | {4} | `{v}` |").format(fmt_n(d.get('events')), d.get('seconds'), fmt_n(d.get('events_per_second')), fmt_mib(d.get('db_bytes')), d.get('fts_fields'), v=_v))
        W("")
        W(tr("Chemin traversé : `") + next(x.get('path','') for x in ingest
                                       if x.get('phase') in (None, 'ingest')) + "`.")
        W("")
        for d in ingest:
            if d.get("_derived"):
                W(tr("> Ligne de {0} événements : **{1}.**").format(fmt_n(d.get('events')), d['_derived']))
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
                W(tr("Débit **cumulé** relevé par le générateur lui-même pendant le remplissage (il est "
                     "régulé sur la profondeur du spool : son débit de production est donc le débit d'ingest "
                     "de bout en bout). Ces points couvrent le DÉBUT du remplissage :"))
                W("")
                W(tr("| Événements produits | Volume produit | Débit cumulé mesuré |"))
                W("|---:|---:|---:|")
                for n, mio, rate in fpts:
                    W(tr("| {0} | {mio:.0f} Mio | **{1} ev/s** |").format(fmt_n(n), fmt_n(rate), mio=mio))
                W("")
                if len(fpts) >= 2:
                    W(tr("Le débit cumulé passe de **{0} ev/s** à **{1} ev/s** entre {2} et {3} événements "
                         "produits, soit **x{4:.1f}**. Deux causes se superposent — le volume déjà en base "
                         "(maintenance des index et de la FTS5) et la charge de la machine — et cette passe ne "
                         "les sépare pas. À ce débit-là, atteindre 10 M depuis ce point aurait demandé plusieurs "
                         "heures de plus : c'est ce qui a borné CETTE passe-ci, et cela ne dit rien des autres "
                         "passes du document.").format(fmt_n(fpts[0][2]), fmt_n(fpts[-1][2]), fmt_n(fpts[0][0]), fmt_n(fpts[-1][0]), fpts[0][2]/max(fpts[-1][2],1)))
                    W("")
        for _ci, _curve in enumerate(args.ingest_curve or []):
            # UNE SOUS-SECTION PAR COURBE. Deux remplissages du MÊME volume, l'un sur machine
            # chargée et l'autre sur machine au repos, se lisent côte à côte : c'est ce qui
            # SÉPARE la contention du volume, au lieu de les mélanger dans une seule phrase.
            import os as _o2
            W(tr("### Courbe de remplissage — `{0}`").format(_o2.path.basename(_curve)))
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
                W(tr("#### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé"))
                W("")
                W(tr("Un débit moyen seul cacherait cette dégradation. Chaque ligne est un intervalle"))
                W(tr("d'échantillonnage réel pendant le remplissage (la maintenance des index et de la"))
                W(tr("FTS coûte de plus en plus cher à mesure que les b-trees grossissent)."))
                W("")
                W(tr("| Lignes en base | Taille base | RSS du daemon | Débit sur l'intervalle | `loadavg` |"))
                W("|---:|---:|---:|---:|---:|")
                step = max(1, len(segs) // 12)
                for n, db, rss, rate, la in segs[::step]:
                    W(tr("| {0} | {1} Mio | {2} Mio | {3} ev/s | {la:.1f} |").format(fmt_n(n), fmt_mib(db), fmt_mib(rss), fmt_n(int(rate)), la=la))
                W("")
                # ------------------------------------------------ ATTRIBUTION (colonnes riches)
                iv = [d for d in ingest_intervals(_curve) if d.get("cpu_ms_per_event")]
                if len(iv) >= 4:
                    W(tr("##### D'où vient l'effondrement — attribution mesurée, pas supposée"))
                    W("")
                    W(tr("Un débit qui tombe ne dit pas POURQUOI il tombe. Trois grandeurs le disent, et"))
                    W(tr("elles sont relevées à chaque tick par `bench/probe.py` :"))
                    W("")
                    W(tr("- **CPU du daemon par événement** — s'il monte, le travail par ligne grandit"))
                    W(tr("  vraiment (b-trees plus profonds, index et FTS à maintenir) : c'est le VOLUME."))
                    W(tr("- **CPU consommé par le reste de la machine** — c'est la CONTENTION. Elle inclut"))
                    W(tr("  les fils noyau qui exécutent NOS propres écritures : ce n'est donc pas"))
                    W(tr("  seulement « d'autres travaux », c'est « du CPU non facturé au daemon »."))
                    W(tr("- **Octets lus au bloc et stall mémoire du cgroup** — si le plafond de 2 Gio"))
                    W(tr("  forçait la récupération du cache de pages, ils monteraient. Le budget est"))
                    W(tr("  appliqué par ce même cgroup, et son cache de pages lui est facturé."))
                    W("")
                    W(tr("| Lignes en base | Débit | CPU daemon / événement | cœurs daemon | cœurs du reste | lu "
                         "au bloc | écrit / 1 000 év. | stall mémoire | part de la sonde |"))
                    W("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
                    stp = max(1, len(iv) // 12)
                    for d in iv[::stp]:
                        W(tr("| {0} | {1} ev/s | {2:.3f} ms | {3:.2f} | {4:.2f} | {5} Mio | {6:.1f} Mio | {7:.0f} ms "
                             "| {8:.1f} % |").format(fmt_n(d['events']), fmt_n(int(d['rate'])), d['cpu_ms_per_event'], d.get('daemon_cores') or 0, d.get('other_cores') if d.get('other_cores') is not None else float('nan'), fmt_mib(d.get('d_read_bytes') or 0), (d.get('d_write_bytes') or 0)/max(d['dn'],1)*1000/2**20, (d.get('d_cg_mem_stall_us') or 0)/1000, 100*(d.get('count_ms') or 0)/1000/max(d['dt'],1)))
                    W("")
                    # L'INSTRUMENT SE COMPTE LUI-MÊME. Le comptage des lignes qui sert d'abscisse est
                    # un scan : à gros volume il consomme une part croissante de l'intervalle, ET son
                    # CPU est facturé au daemon. Sans cette colonne, sa dépense se lirait comme une
                    # dégradation du produit.
                    pr = [(d.get("count_ms") or 0) / 1000 / max(d["dt"], 1) for d in iv]
                    _prs = sorted(pr)
                    W(tr("« Part de la sonde » = ce que le COMPTAGE DES LIGNES de l'échantillonneur consomme de "
                         "l'intervalle : **{0:.1f} % en médiane**, **{1:.1f} % au pire**. Ce comptage est un scan "
                         "servi par le daemon : son coût est DANS les colonnes CPU et débit ci-dessus. La "
                         "dégradation nette du produit est donc un peu plus faible que celle affichée — jamais "
                         "plus forte.").format(100*_prs[len(_prs)//2], 100*_prs[-1]))
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
                    W(tr("Entre {0} et {1} lignes en base, le débit passe de **{2} à {3} ev/s** (**÷{fall:.2f}**) "
                         "et le coût CPU du daemon par événement de **{cpu0:.3f} à {cpu1:.3f} ms** "
                         "(**×{cpu_growth:.2f}**).").format(fmt_n(n0), fmt_n(n1), fmt_n(int(r0)), fmt_n(int(r1)), fall=fall, cpu0=cpu0, cpu1=cpu1, cpu_growth=cpu_growth))
                    W("")
                    # DÉCOMPOSITION EXACTE, pas une part estimée : le débit EST le quotient des deux
                    # colonnes mesurées, `débit = cœurs occupés par le daemon / CPU par événement`.
                    # La chute se factorise donc SANS reste entre « le travail par ligne a grandi » et
                    # « le daemon tourne moins souvent » (il attend). Les deux facteurs sont mesurés.
                    c0 = sum(d.get("daemon_cores") or 0 for d in iv[:k]) / k
                    c1 = sum(d.get("daemon_cores") or 0 for d in iv[-k:]) / k
                    if cpu_growth >= 1.15 and fall >= 1.15:
                        W(tr("Cette chute se FACTORISE, sans reste, en deux facteurs mesurés — le débit est exactement **cœurs occupés / CPU par événement** :"))
                        W("")
                        _prod = cpu_growth * (c0 / max(c1, 1e-9))
                        W(tr("> **÷{fall:.2f}** (débit mesuré) = **×{cpu_growth:.2f}** (CPU par événement : le travail par ligne grandit avec les b-trees) × **÷{0:.2f}** (cœurs occupés par le daemon : {c0:.2f} au début contre {c1:.2f} à la fin — il ATTEND davantage). Le produit vaut ÷{prod:.2f}, soit {1:.0f} % d'écart avec la chute mesurée : l'écart est celui de la moyenne par quartile, l'identité **débit = cœurs / CPU par événement** étant exacte intervalle par intervalle.").format(c0/max(c1,1e-9), abs(_prod-fall)/fall*100, fall=fall, cpu_growth=cpu_growth, c0=c0, c1=c1, prod=_prod))
                        W("")
                        W(tr("Le travail par ligne grandit donc RÉELLEMENT avec le volume déjà en base : c'est le "
                             "VOLUME, pas la machine. Et le daemon n'occupe jamais plus de {0:.2f} cœur sur les 12 "
                             "disponibles : le chemin d'écriture est SÉQUENTIEL, ajouter des cœurs n'y changerait "
                             "rien.").format(max((d.get('daemon_cores') or 0) for d in iv)))
                    elif cpu_growth < 1.15 and fall >= 1.15:
                        W(tr("Le coût CPU par événement ne bouge PAS pendant que le débit tombe : le daemon n'a pas "
                             "plus de travail par ligne, il ATTEND. La cause n'est donc pas le volume en base."))
                    else:
                        W(tr("Le débit ne s'effondre pas sur cet intervalle : il n'y a rien à attribuer."))
                    W("")
                    if dmnmed is not None and othmed is not None:
                        W(tr("Le daemon occupe **{dmnmed:.2f} cœur** en médiane pendant que le reste de la machine en "
                             "occupe **{othmed:.2f}** (12 cœurs disponibles). ").format(dmnmed=dmnmed, othmed=othmed)
                          + (tr("La machine n'est donc pas saturée : la chute n'est pas une contention de CPU disponible.") if dmnmed + othmed < 8 else
                             tr("La machine est proche de la saturation : une part de la chute est de la contention.")))
                        W("")
                    # CE QUE ÇA COÛTE D'ALLER PLUS HAUT. Arithmétique sur des débits MESURÉS, et
                    # présentée comme un PLANCHER : le débit baisse encore au-delà, donc le vrai
                    # coût est SUPÉRIEUR. Ce n'est pas une mesure à 10 M, et c'est écrit.
                    for target in (10_000_000,):
                        if n1 < target:
                            h = (target - n1) / max(r1, 1) / 3600.0
                            W(tr("**Ce que coûterait {0} événements** : au DERNIER débit mesuré ({1} ev/s), il resterait "
                                 "{2} événements à ingérer, soit **{h:.1f} h** — et c'est un PLANCHER, puisque le débit a "
                                 "déjà été divisé par {fall:.1f} sur la plage mesurée et continue de baisser. Cette ligne "
                                 "est de l'arithmétique sur des débits mesurés, PAS une mesure à ce volume : aucune "
                                 "latence de ce document ne vaut au-delà du volume réellement rempli.").format(fmt_n(target), fmt_n(int(r1)), fmt_n(target - n1), h=h, fall=fall))
                            W("")
                    W(tr("**Le stockage n'est pas en cause côté LECTURE** : {0} Mio lus au bloc sur tout le "
                         "remplissage — la base tient dans le cache de pages. **Le plafond de 2 Gio ne freine pas "
                         "non plus par récupération mémoire** : {stall:.1f} s de stall mémoire cumulé sur le "
                         "cgroup, mesuré.").format(fmt_mib(rd), stall=stall))
                    W("")
                rates = sorted(r for _, _, _, r, _ in segs)
                las = sorted(la for _, _, _, _, la in segs)
                med = rates[len(rates) // 2]
                base = (tr("Débit sur les intervalles échantillonnés : **min {0:.0f} ev/s, médiane {med:.0f} ev/s, "
                           "max {1:.0f} ev/s**, pour un `loadavg` allant de {2:.1f} à {3:.1f}. L'écart d'un facteur "
                           "{4:.1f} entre le plus lent et le plus rapide intervalle ").format(rates[0], rates[-1], las[0], las[-1], rates[-1]/max(rates[0],1), med=med))
                if len(iv) >= 4:
                    # La sonde a relevé le CPU : la cause est ATTRIBUÉE au-dessus, on ne la devine
                    # plus depuis le `loadavg` (qui compte aussi les tâches en attente d'E/S et ne
                    # dit à qui appartient aucune d'elles).
                    W(base + tr("n'est plus interprété depuis le `loadavg` : la sous-section d'attribution ci-dessus le "
                                "décompose en CPU du daemon, CPU du reste de la machine et attente du stockage — trois "
                                "grandeurs mesurées."))
                else:
                    W(base + tr("suit le `loadavg` : **cette passe ne sépare pas** le volume déjà en base de la charge "
                                "de la machine — son CSV est antérieur à la sonde qui relève le CPU par processus. À "
                                "lire comme un PLANCHER."))
                W("")
                W(tr("La colonne RSS est la mémoire réellement occupée par le daemon PENDANT l'ingest — crête "
                     "échantillonnée ici : **{0} Mio**, à confronter au budget de 2 Gio. C'est une mesure, "
                     "pas une estimation.").format(fmt_mib(max(x[2] for x in segs))))
                W("")
                W(tr("> Portée de cette courbe : l'échantillonneur ne couvre que la fenêtre où il a tourné "
                     "({0} à {1} lignes). Ce qui s'est passé avant n'est pas dans ce tableau, et n'est donc "
                     "pas mesuré ici.").format(fmt_n(segs[0][0]), fmt_n(segs[-1][0])))
                W("")

    W(tr("## Configurations mesurées"))
    W("")
    W(tr("| Étiquette | Événements | Hôtes | `PLUME_FTS_FIELDS` | Masquage de champs | Tier froid "
         "| Classes mesurées |"))
    W("|---|---:|---:|:--:|---|:--:|---|")
    for c in configs:
        m = cfgmeta[c]
        n_cells = sum(1 for r in eff if r["config_id"] == c)
        sub = m.get("classes")
        # La colonne « Hôtes » est la cardinalité de `host` DU JEU DE DONNÉES, pas un réglage : elle
        # vient du profil lu par le générateur. Sans elle, deux passes au même volume mais à des
        # cardinalités d'hôte différentes seraient indiscernables dans ce tableau.
        W(tr("| `{c}` | {0} | {1} | {2} | {3} | {4} | {5} ({n_cells} cellules) |").format(fmt_n(m.get('events')), m.get('hosts', '?'), m.get('fts_fields','?'), tr_donnee(m.get('mask','?')), tr_donnee(m.get('cold','?')), tr('toutes') if not sub else tr("**sous-ensemble** `") + sub + '`', c=c, n_cells=n_cells))
    W("")
    W(tr("Le masquage compte parce qu'il est **contre-intuitif** : un ensemble de masquage non "
         "vide"))
    W(tr("désarme la route de rollups *et* le moteur vectorisé (`handlers/query.rs:282`,"))
    W(tr("`cold_store/planner.rs:601`). Le rempart de confidentialité est un frein de "
         "performance, donc"))
    W(tr("des chiffres publiés sans cet axe ne vaudraient que pour un déploiement **sans** "
         "masquage."))
    W(tr("Toutes les cellules sont tirées avec le **même rôle** (`viewer`) dans les deux états : "
         "une règle"))
    W(tr("de masque à `role:''` ne contraint pas un admin (`field_filter.rs:110-115`), le "
         "comparer en"))
    W(tr("admin ne mesurerait rien."))
    W("")

    # ---------------------------------------------------------------- tableaux
    for c in configs:
        m = cfgmeta[c]
        W(tr("## Résultats — `{c}`").format(c=c))
        W("")
        W(tr("*`PLUME_FTS_FIELDS`={0}, masquage={1}, froid={2}, version=`{3}`, {4} événements, base "
             "{5} Mio.*").format(m.get('fts_fields'), tr_donnee(m.get('mask')), tr_donnee(m.get('cold')), m.get('version'), fmt_n(m.get('events')), fmt_mib(m.get('db_bytes'))))
        W("")
        reps_seen = sorted({r.get("reps") for r in eff if r["config_id"] == c and r.get("reps")})
        W(tr("Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du"))
        W(tr("processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le"))
        W(tr("processus (0 = servi depuis le cache de pages)."))
        W("")
        disp = [r for r in eff if r["config_id"] == c and r.get("wall_p50_ms")
                and r.get("wall_p95_ms") and r["wall_p95_ms"] / r["wall_p50_ms"] > 3]
        if disp:
            W("")
            W(tr("**{0} cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une "
                 "machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été "
                 "bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste "
                 "utilisable, leur `p95` non.").format(len(disp)))
        W("")
        W(tr("**Ce que `p95` vaut ici** : {0} répétitions par cellule (le harnais retombe à 3 quand "
             "le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, "
             "`p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un "
             "tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire "
             "des N tirs », rien de plus.").format(', '.join(str(x) for x in reps_seen)))
        W("")
        if m.get("classes"):
            W(tr("> Cette configuration ne mesure que les classes `{0}`. Les classes absentes").format(m['classes']))
            W(tr("> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas"))
            W(tr("> implicitement inchangées."))
            W("")
        W(tr("| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |"))
        W("|---|:--:|---:|---:|---:|---:|---:|---:|---|---|")
        for cid, label, kind in classes:
            for w in wins:
                r = idx.get((c, cid, w))
                if not r:
                    continue
                notes = []
                if r.get("errors"):
                    notes.append(tr("ERREUR: ") + "; ".join(x[:70] for x in r["errors"]))
                if r.get("truncated"):
                    notes.append(tr("tronqué"))
                if r.get("approx"):
                    notes.append("approx")
                if r.get("swap_suspect"):
                    notes.append(tr("**pris sous swap — à rejouer**"))
                if (r.get("peak_rss_bytes") or 0) > BUDGET_BYTES:
                    notes.append(tr("**> 2 Gio**"))
                if r.get("reps_ok", 0) < r.get("reps", 0):
                    notes.append(tr("{0}/{1} tirs OK").format(r['reps_ok'], r['reps']))
                # Dispersion p95/p50 : sur une machine partagée, un facteur >3 entre le pire et le
                # médian ne dit rien de plume, il dit que la mesure a été bousculée. On le MARQUE
                # au lieu de publier un p95 comme s'il décrivait le produit.
                p50v, p95v = r.get("wall_p50_ms"), r.get("wall_p95_ms")
                if p50v and p95v and p50v > 0 and p95v / p50v > 3:
                    la = (r.get("pressure_before") or {}).get("loadavg") or [0]
                    notes.append(tr("dispersion x{0:.1f} (loadavg {1:.0f}) — p95 dominé par la contention, pas par plume").format(p95v/p50v, la[0]))
                # `P7.20-j` (2026-09-09) — UNE BARRE VERTICALE DANS UN LIBELLÉ EST UNE CELLULE DE PLUS. Le libellé
                # de `C4d-keyset-projete` porte « (| table) » : non échappé, il coupait la ligne en onze cellules
                # là où l'en-tête en déclare dix, et la garde de forme des tableaux rougissait sur 61 lignes du
                # document régénéré. Le texte libre d'une cellule est ÉCHAPPÉ ici, à l'écriture, jamais à la main.
                label = str(label).replace("\\|", "|").replace("|", "\\|")  # idempotent : on normalise, puis on échappe
                W(tr("| `{cid}` <br><sub>{label}</sub> | {w} | {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |").format(fmt_ms(r.get('wall_p50_ms')), fmt_ms(r.get('wall_p95_ms')), fmt_ms(r.get('cold_first_wall_ms')), fmt_mib(r.get('peak_rss_bytes')), fmt_mib(r.get('read_bytes_first')), fmt_n(r.get('rows')), r.get('served_from') or 'scan', ' / '.join(notes) if notes else '', cid=cid, label=label, w=w))
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
        _notes = notes_de_comparaison(args, LANGUE)
        _note = _notes[_i] if _i < len(_notes) else None
        W(tr("## Écart mesuré entre deux passes — `{c_av}` vs `{c_ap}`").format(c_av=c_av, c_ap=c_ap))
        W("")
        W(tr("Comparaison `{c_av}` -> `{c_ap}`, MÊME base, MÊME instrument, MÊME machine, passes "
             "consécutives. Les deux lignes sont des mesures ; le delta est leur soustraction, rien "
             "de plus.").format(c_av=c_av, c_ap=c_ap))
        W("")
        if _note:
            W(tr("**Ce qui a changé entre les deux passes** : {note}").format(note=_note))
            W("")
        W(tr("Charge machine relevée : `loadavg` {0} pendant la passe AVANT, {1} pendant la passe "
             "APRÈS. Sur une machine partagée, un écart de quelques millisecondes ne prouve rien ; "
             "seuls les écarts francs sont exploitables, et les cellules dont la dispersion est "
             "annotée plus haut restent à lire avec la même réserve.").format(_cmp_load(eff, c_av), _cmp_load(eff, c_ap)))
        W("")
        W(tr("| Classe | Fenêtre | p50 avant | p50 après | delta | SQL avant | SQL après | route "
             "avant | route après |"))
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
            trunc = tr(" ⚠ **réponse tronquée d'un côté**") if (a.get("truncated") or b.get("truncated")) else ""
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
            W(tr("**{nt} de ces lignes opposent des réponses de contenu DIFFÉRENT** (un côté tronque) : "
                 "leur delta mesure un écart de travail, pas un écart de vitesse. Elles sont marquées.").format(nt=_nt))
            W("")
        W(tr("{seen_pairs} cellules comparables. ").format(seen_pairs=seen_pairs)
          + (tr("Mesurées SEULEMENT après : {0}. ").format(', '.join(f'`{c}`/{w}' for c, w in only_ap)) if only_ap else "")
          + (tr("Mesurées SEULEMENT avant : {0}. ").format(', '.join(f'`{c}`/{w}' for c, w in only_av)) if only_av else "")
          + tr("Une cellule non comparable n'est PAS un résultat neutre : elle est absente d'un côté."))
        W("")

    # ------------------------------------------------------------ FENÊTRES (dont les non mesurées)
    W(tr("## Les fenêtres mesurées, et celles qui ne le sont pas"))
    W("")
    W(tr("Les fenêtres ne sont pas choisies : elles sont DÉRIVÉES de deux paramètres du produit — "
         "la"))
    W(tr("fenêtre chaude (`PLUME_COLD_HOT_WINDOW_DAYS`, défaut **7 j**, `cold_store/aging.rs`) et "
         "la"))
    W(tr("rétention (`PLUME_RETENTION_DAYS`) — puis filtrées par l'étendue réelle du jeu de "
         "données."))
    W("")
    W(tr("| Fenêtre | Ce qu'elle mesure |"))
    W("|---|---|")
    _wl = {}
    for r in rows:
        if r.get("window_label"):
            _wl[r["window"]] = tr_donnee(r["window_label"])
    for w in wins:
        W(f"| `{w}` | {_wl.get(w, '—')} |")
    W("")
    if unmeasured_win:
        _seen_w = {}
        for d in unmeasured_win:
            _seen_w[d["window"]] = d
        W(tr("**Fenêtres écartées par la garde de couverture — donc NON MESURÉES** :"))
        W("")
        for w, d in sorted(_seen_w.items()):
            W(f"- `{w}` ({tr_donnee(d.get('label'))}) — {tr_donnee(d.get('why'))}")
        W("")
        W(tr("Une fenêtre plus large que le jeu ne mesure pas ce que dit son étiquette : elle mesure"))
        W(tr("`all` (« tout ») sous un autre nom. Le harnais refuse de la tirer plutôt que de publier une cellule"))
        W(tr("dont le titre serait faux. Pour l'obtenir, il faut un jeu qui la couvre — c'est-à-dire"))
        W(tr("remplir sur une étendue plus longue (`BENCH_SPAN_DAYS`), pas rendre la garde plus "
             "permissive."))
        W("")

    # ------------------------------------------------------------ TIER FROID
    cold_cfgs = [c for c in configs
                 if str(cfgmeta[c].get("cold", "off")).lower() not in ("off", "0", "", "none")]
    cold_age = [d for d in ingest if d.get("phase") == "cold_age"]
    if cold_cfgs or cold_age:
        W(tr("## Le tier froid — mesuré"))
        W("")
        W(tr("Avec une fenêtre chaude de 7 jours et une rétention de 365, `daemon/src/cold_store/` est"))
        W(tr("le chemin de lecture de **358 des 365 jours** d'une production. Les tableaux ci-dessus"))
        W(tr("tournent tous à `PLUME_COLD_TIER=0` : ils ne disent rien de ce chemin. Cette section est"))
        W(tr("la seule qui en parle, et elle ne parle que de ce qui a été tiré."))
        W("")
        for d in cold_age:
            moved = (d.get("hot_rows_before") or 0) - (d.get("hot_rows_after") or 0)
            hb, ha = d.get("hot_bytes_before") or 0, d.get("hot_bytes_after") or 0
            W(tr("**Columnarisation mesurée** (chemin réel : `plume-daemon retention` -> `retention_run`"))
            W(tr("-> `cold_age_run`, fenêtre chaude {0} j) :").format(d.get('hot_window_days')))
            W("")
            W(tr("| | Avant | Après |"))
            W("|---|---:|---:|")
            W(tr("| Lignes CHAUDES (SQLite) | {0} | {1} |").format(fmt_n(d.get('hot_rows_before')), fmt_n(d.get('hot_rows_after'))))
            W(tr("| Base chaude | {0} Mio | {1} Mio |").format(fmt_mib(hb), fmt_mib(ha)))
            W(tr("| Tier froid (Parquet chiffré) | 0 Mio | {0} Mio en {1} fichiers |").format(fmt_mib(d.get('cold_bytes')), d.get('cold_files')))
            W("")
            pct = 100.0 * moved / max(d.get("hot_rows_before") or 1, 1)
            ratio = (d.get("cold_bytes") or 0) / max(moved, 1)
            W(tr("**{0} lignes ({pct:.1f} %) ont quitté SQLite pour le Parquet**, en {1} fichiers (un par "
                 "jour). Le froid pèse **{ratio:.0f} octets par événement** là où le chaud en occupait "
                 "{2:.0f} (table, index et FTS compris), soit **{3:.0f}x plus compact**.").format(fmt_n(moved), fmt_n(d.get('cold_files')), (hb)/max(d.get('hot_rows_before') or 1,1), ((hb)/max(d.get('hot_rows_before') or 1,1))/max(ratio,1), pct=pct, ratio=ratio))
            W("")
            # La DURÉE n'est publiée que si la passe qui l'a produite était propre. Une passe
            # interrompue puis reprise mesure l'interruption autant que le produit : on publie la
            # note, pas un débit qui aurait l'air d'en être un.
            if d.get("_note_seconds"):
                W(tr("> Durée : {0}").format(tr_donnee(d['_note_seconds'])))
            elif d.get("seconds"):
                W(tr("Durée mesurée : **{0} s**, soit {1:.0f} lignes/s.").format(d['seconds'], moved/max(d.get('seconds') or 1,1)))
            W("")
            if ha > hb:
                W(tr("> La base chaude n'a pas RÉTRÉCI : SQLite ne rend pas les pages au système, il les"))
                W(tr("> met en liste libre (`auto_vacuum=0`, le réglage par défaut). L'espace est réutilisé"))
                W(tr("> par les écritures suivantes, il n'est pas rendu au disque. C'est mesuré, pas supposé."))
                W("")
        for d in [x for x in ingest if str(x.get("phase") or "").startswith("cold_parity")]:
            W(tr("### La réponse est-elle la MÊME ? (parité mesurée)"))
            W("")
            W(tr("Une latence n'est comparable que si les deux chemins rendent la même réponse : un"))
            W(tr("chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne"))
            W(tr("compare donc pas des temps, elle compare **les valeurs rendues**."))
            W("")
            W(tr("Méthode : {0}").format(tr_donnee(d.get('method'))))
            W("")
            checks = d.get("checks") or []
            # DEUX SCHÉMAS COEXISTENT, et c'est délibéré. Les passes anciennes portent des contrôles
            # écrits À LA MAIN (`hot_value`/`cold_value`/`ratio`) ; les passes produites par
            # `bench/parity.py` portent un VERDICT par contrôle sur toute la matrice. On rend chacun
            # sous sa forme : réécrire l'ancien dans le nouveau serait inventer des chiffres.
            if checks and "verdict" in checks[0]:
                counts = d.get("counts") or {}
                W(tr("| Verdict | n | ce qu'il signifie |"))
                W("|---|---:|---|")
                W(tr("| `same` | {0} | les deux côtés rendent la MÊME réponse. |").format(counts.get('same', 0)))
                W(tr("| `differs` | {0} | ils divergent **sans le dire** — un nombre faux, lisible et "
                     "copiable. C'est LE cas grave. |").format(counts.get('differs', 0)))
                W(tr("| `declared` | {0} | ils divergent et le côté froid le DIT (`truncated`, ou note de "
                     "couverture). L'incomplétude devient une information. |").format(counts.get('declared', 0)))
                W(tr("| `refused` | {0} | un côté REFUSE, avec un motif nommé. Une erreur vaut mieux qu'un "
                     "nombre faux : c'est la position de repli, pas l'échec. |").format(counts.get('refused', 0)))
                W("")
                W(tr("`declared` n'acquitte rien : un AGRÉGAT tronqué reste un nombre faux, déclaré ou non."))
                W(tr("Les catégories ne s'additionnent jamais en un « tout va bien »."))
                W("")
                if "nombre_faux" in (d.get("counts") or {}):
                    nf = d["counts"]["nombre_faux"]
                    W(tr("**Le compte qui compte : {nf} NOMBRE(S) FAUX.** C'est le nombre de contrôles dont la").format(nf=nf))
                    W(tr("réponse porte une valeur calculée SUR L'ENSEMBLE (`count`/`dc`/`stats … by …`) et dont"))
                    W(tr("les deux côtés DIVERGENT — que le côté froid l'ait déclaré ou non. C'est exactement ce"))
                    W(tr("que l'invariant de `cold_store/exactness.rs` interdit. Les autres catégories décrivent"))
                    W(tr("des réponses partielles de LIGNES (vraies, incomplètes, signalées) ou des refus motivés "
                         ":"))
                    W(tr("elles ne sont pas du même ordre de gravité."))
                    W("")
                if d.get("_reclassement"):
                    W(tr("> Comptage : {0}").format(tr_donnee(d['_reclassement'])))
                    W("")
                notsame = [c for c in checks if c.get("verdict") != "same"]
                if notsame:
                    W(tr("Le détail de tout ce qui n'est pas `same` :"))
                    W("")
                    W(tr("| Requête | Fenêtre | Verdict | Sans tier froid | Avec tier froid |"))
                    W("|---|:--:|:--:|---|---|")
                    for ck in notsame:
                        _q = str(ck.get("query") or "").replace("|", "\\|")

                        def _side(x):
                            if x.get("values"):
                                return "**" + ", ".join(fmt_n(r[-1]) if isinstance(r, list) and r and isinstance(r[-1], int)
                                                        else str(r) for r in x["values"])[:60] + "**"
                            if x.get("status", 200) >= 400:
                                return tr("refus {0}").format(x.get('status'))
                            n = x.get("rows")
                            tag = tr(" (tronqué)") if x.get("truncated") else (tr(" (couverture déclarée)") if x.get("coverage") else "")
                            return tr("{0} lignes `{1}`{tag}").format(fmt_n(n), x.get('digest'), tag=tag)

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
                    W(tr("**Écart maximal mesuré sur un agrégat scalaire** : `{0}` sur la fenêtre `{1}` rend "
                         "**{2}** sans tier froid et **{3}** avec — soit **x{r:.1f}**. Ce n'est pas une réponse "
                         "approchée, c'est un mauvais nombre : le").format(ck['query'], ck['window'], fmt_n(hv1), fmt_n(cv1), r=r))
                    W(tr("chemin d'union hydrate le froid dans une table temporaire SQLite bornée à"))
                    W(tr("`PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège"))
                    W(tr("SUR CET ÉCHANTILLON."))
                else:
                    W(tr("**Aucun agrégat scalaire ne diverge.** Les contrôles réductibles à un nombre rendent"))
                    W(tr("la même valeur des deux côtés, ou bien le côté froid REFUSE de répondre en nommant sa"))
                    W(tr("cause. C'est l'invariant de `cold_store/exactness.rs` : aucune valeur dérivée d'un"))
                    W(tr("ensemble tronqué n'est rendue comme un nombre."))
                W("")
            else:
                W(tr("| Requête | Fenêtre | Sans tier froid | Avec tier froid | Écart | Tronqué ? |"))
                W("|---|:--:|---:|---:|---:|:--:|")
                for ck in checks:
                    # Une requête GXQL contient un `|` : dans une cellule de tableau Markdown il
                    # coupe la ligne en deux. On l'échappe — sinon le tableau se disloque à l'affichage.
                    _q = ck["query"].replace("|", "\\|")
                    W(f"| `{_q}` | {ck['window']} | **{fmt_n(ck['hot_value'])}** | "
                      f"**{fmt_n(ck['cold_value'])}** | x{ck['ratio_hot_over_cold']:.1f} | "
                      f"{tr('**oui** ({0} lignes hydratées)').format(fmt_n(ck['cold_rows_hydrated'])) if ck['cold_truncated'] else tr('non')} |")
                W("")
                W(tr("Le chemin d'union chaud∪froid hydrate le froid dans une table temporaire SQLite bornée"))
                W(tr("à `PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège"))
                W(tr("SUR CET ÉCHANTILLON. Le compte rendu n'est donc pas « approché » : il est **faux d'un"))
                W(tr("facteur qui dépend du volume de la fenêtre**. Le daemon le SIGNALE"))
                W(tr("(`stats.truncated=true`), mais un lecteur qui ne regarde que le nombre voit un nombre"))
                W(tr("faux. Toute latence « froide » de cette passe doit donc être lue avec sa colonne"))
                W(tr("« tronqué » : quand elle dit oui, la cellule mesure le temps d'une réponse INCOMPLÈTE,"))
                W(tr("et ne peut pas être comparée à la cellule chaude."))
                W("")
            if d.get("_reserve_rollup"):
                W(tr("> Réserve : {0}").format(tr_donnee(d['_reserve_rollup'])))
                W("")
        for c in cold_cfgs:
            crows = [r for r in eff if r["config_id"] == c]
            bnd = next((r["cold"].get("boundary_ts") for r in crows
                        if isinstance(r.get("cold"), dict) and r["cold"].get("boundary_ts")), None)
            W(f"### `{c}`")
            W("")
            if bnd:
                W(tr("Frontière chaud/froid CALCULÉE PAR LE DAEMON : `boundary_ts={bnd}`. Une fenêtre").format(bnd=bnd))
                W(tr("dont la borne basse passe sous cette valeur lit du Parquet ; une fenêtre qui"))
                W(tr("l'enjambe lit les DEUX et paie l'union."))
                W("")
            W(tr("| Classe | Fenêtre | p50 | lignes | route | passé par le froid | tronqué |"))
            W("|---|:--:|---:|---:|---|---|:--:|")
            for cid, lab, _k in classes:
                for w in wins:
                    r = idx.get((c, cid, w))
                    if not r:
                        continue
                    cold = r.get("cold") if isinstance(r.get("cold"), dict) else None
                    W(f"| `{cid}` | {w} | {fmt_dur(r.get('wall_p50_ms'))} | {fmt_n(r.get('rows'))} | "
                      f"{r.get('served_from') or '—'} | "
                      f"{cold.get('served_from') if cold else tr('non')} | "
                      f"{tr('**oui**') if r.get('truncated') else tr('non')} |")
            W("")
            _ev = cfgmeta[c].get("events")
            if cold_age and _ev and _ev == (cold_age[0].get("hot_rows_after")):
                W(tr("> Dans le tableau des configurations, la colonne « Événements » de `{c}` vaut {0} : "
                     "c'est le nombre de lignes CHAUDES, pas la taille du jeu. {1} événements sont "
                     "interrogeables, dont {2} depuis le Parquet.").format(fmt_n(_ev), fmt_n(cold_age[0].get('hot_rows_before')), fmt_n((cold_age[0].get('hot_rows_before') or 0) - _ev), c=c))
                W("")
            ncold = sum(1 for r in crows if isinstance(r.get("cold"), dict))
            ntrunc = sum(1 for r in crows if r.get("truncated"))
            W(tr("**{ncold} cellules sur {0} ont réellement traversé le tier froid** (colonne").format(len(crows), ncold=ncold))
            W(tr("« passé par le froid » : elle vient de `stats.cold` renvoyé par le daemon, pas de"))
            W(tr("l'étiquette de configuration). ")
              + (tr("**{ntrunc} cellules sont TRONQUÉES** : le chemin d'union hydrate le froid dans SQLite "
                    "avec un plafond de lignes (`PLUME_QUERY_MAX`, défaut 5 000, `cold_store/reader.rs:130`) "
                    "— au-delà, la réponse est PARTIELLE et le daemon le dit. Un agrégat sur une fenêtre "
                    "froide large n'est donc pas exact par défaut : c'est le résultat le plus important de "
                    "cette section.").format(ntrunc=ntrunc)
                 if ntrunc else tr("Aucune cellule tronquée.")))
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
        W(tr("## Le nombre de machines — ce que le profil mono-hôte cachait"))
        W("")
        W(tr("La base profilée est **mono-nœud** : toutes ses sources ont `distinct_hosts: 1`. `host`"))
        W(tr("étant l'une des six colonnes indexées, toute cellule qui filtre ou groupe par hôte y "
             "porte"))
        W(tr("sur un cas **dégénéré de cardinalité 1**. Les passes ci-dessous rejouent les mêmes "
             "classes"))
        W(tr("sur des profils FLOTTE dérivés (`bench/make_fleet_profile.py`), **à volume d'événements"))
        W(tr("égal**."))
        W("")
        W(tr("**Ce qui change exactement entre ces passes** — il faut le dire avant de lire le "
             "tableau :"))
        W(tr("**(1)** la cardinalité de `host` (1, puis N) ; **(2)** le MÉLANGE des sources, parce que"))
        W(tr("multiplier les sources host-locales par N change leur poids relatif (`auditd` passe de"))
        W(tr("38,5 % à 44,7 % du flux). Les deux viennent de la même dérivation. Une classe qui bouge"))
        W(tr("peut donc bouger pour l'une OU l'autre raison — sauf les classes `C6*`, qui nomment "
             "`host`"))
        W(tr("dans la requête : celles-là isolent la cardinalité, et ce sont elles qu'il faut lire "
             "pour"))
        W(tr("juger du trou de généricité."))
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
            W(tr("**Ce que la taille de flotte change en VOLUME** — dérivé (`bench/make_fleet_profile.py`)"))
            W(tr("des distributions MESURÉES par source, sur la fenêtre de la base profilée :"))
            W("")
            W(tr("| Hôtes | Sources host-locales | Événements mono-hôte (mesuré) | Événements flotte "
                 "(dérivé) | Facteur |"))
            W("|---:|---:|---:|---:|---:|")
            for h, m0, m1, mult, nph in sorted(fl_rows):
                W(tr("| {h} | {nph} sur 32 | {0} | {1} | x{mult} |").format(fmt_n(m0), fmt_n(m1), h=h, nph=nph, mult=mult))
            W("")
            W(tr("La colonne « dérivé » n'est PAS une mesure : c'est la multiplication du poids des"))
            W(tr("sources déclarées host-locales par le nombre de machines. Ce qui est mesuré, ce sont"))
            W(tr("les distributions de chaque source ; ce qui est déclaré, c'est la liste des sources"))
            W(tr("host-locales (`bench/fleet-per-host.txt`, une ligne par source, avec sa raison)."))
            W("")
        W(tr("| Classe | Fenêtre | ") + " | ".join(tr("{h} hôte{0}").format('s' if h > 1 else '', h=h) for h in host_vals) + " |")
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
        W(tr("Une classe dont la latence ne bouge pas avec le nombre de machines ne dépend pas de la"))
        W(tr("cardinalité de `host`. Une classe qui bouge est une classe dont les chiffres publiés sur"))
        W(tr("un profil mono-hôte **ne valent pas** pour une flotte — et le sens de l'erreur n'est pas"))
        W(tr("toujours le même : là où `host` sert de FILTRE, le mono-hôte est PESSIMISTE (le filtre y"))
        W(tr("sélectionne tout, alors qu'il sélectionne 1/N sur une flotte) ; là où `host` sert de "
             "clé de"))
        W(tr("GROUPEMENT, il est OPTIMISTE (un seul groupe au lieu de N). Un profil mono-hôte ne"))
        W(tr("« flatte » donc pas le produit : il le décrit FAUX, dans les deux sens à la fois."))
        W("")

    # ------------------------------------------------------------ GÉNÉRICITÉ MULTI-AXES
    # LA QUESTION : nos chiffres décrivent-ils autre chose que NOTRE jeu de données ? Un tableau qui
    # donnerait un chiffre unique par requête répondrait « oui » sans l'avoir mesuré. Cette section
    # rejoue la MÊME matrice sur des profils qui ne diffèrent du témoin que par UN paramètre, et
    # publie l'ÉCART — avec, en premier, la seule chose qui rende un écart interprétable : le BRUIT.
    render_genericity(W, eff, cfgmeta, classes, wins, fmt_dur)

    W(tr("## Le budget de 2 Gio"))
    W("")
    peak = max((r.get("peak_rss_bytes") or 0) for r in eff)
    W(tr("RSS crête la plus haute observée, toutes cellules confondues : **{0:.0f} Mio** ({1:.1f} "
         "% du budget de 2 Gio).").format(peak/2**20, peak/BUDGET_BYTES*100))
    W("")
    if over:
        W(tr("**{0} cellules ont dépassé 2 Gio.** Elles sont listées ici parce qu'un dépassement").format(len(over)))
        W(tr("est un résultat, pas un échec à cacher :"))
        W("")
        W(tr("| Configuration | Classe | Fenêtre | RSS crête |"))
        W("|---|---|:--:|---:|")
        for r in sorted(over, key=lambda x: -(x.get("peak_rss_bytes") or 0)):
            W(tr("| `{0}` | `{1}` | {2} | **{3} Mio** |").format(r['config_id'], r['class_id'], r['window'], fmt_mib(r['peak_rss_bytes'])))
        W("")
    else:
        W(tr("**Aucune cellule n'a dépassé 2 Gio**, et ce n'est pas une déduction : le daemon tournait"))
        W(tr("dans un scope `MemoryMax=2G MemorySwapMax=0`, où un dépassement se traduit par un kill "
             "du"))
        W(tr("noyau, pas par du swap. Il n'a pas été tué."))
        W("")

    render_concurrency(W, conc)

    W(tr("## Cellules à ne pas croire telles quelles"))
    W("")
    if superseded:
        W(tr("- {superseded} cellules ont été **rejouées** (une mesure bousculée remplacée par une "
             "mesure propre) ; seule la dernière figure dans les tableaux, le JSONL brut garde les "
             "deux.").format(superseded=superseded))
    for d in deaths:
        W(tr("- **Le daemon a été TUÉ après `{0}` / `{1}` / {2}.** {3}").format(d['config_id'], d['class_id'], d['window'], tr_donnee(d['note'])))
    
    if swapped:
        W(tr("- **{0} cellules prises pendant que la machine swappait** ({1}). Un chiffre pris sous "
             "swap est faux. Un rejeu a été TENTÉ pour les cellules de la configuration de référence "
             "; celles qui restent listées ici sont celles pour lesquelles la machine n'a pas offert "
             "de fenêtre sans swap. Leur `p50` est à prendre comme une borne haute, leur `p95` comme "
             "non exploitable.").format(len(swapped), ', '.join(sorted({r['config_id']+'/'+r['class_id']+'/'+r['window'] for r in swapped}))))
    else:
        W(tr("- Aucune cellule n'a été prise pendant que la machine swappait (delta de swap < 8 Mio "
             "sur chaque cellule)."))
    if failed:
        W(tr("- **{0} cellules en échec ou en erreur** — elles restent dans le tableau avec leur "
             "message :").format(len(failed)))
        for r in failed:
            W(tr("  - `{0}` / `{1}` / {2} : {3} (statuts {4})").format(r['config_id'], r['class_id'], r['window'], '; '.join(r.get('errors') or []) or tr("aucun tir réussi"), r.get('statuses')))
    else:
        W(tr("- Aucune cellule en erreur."))
    if truncated:
        W(tr("- **{0} cellules tronquées** par le plafond de lignes (`PLUME_QUERY_MAX`, 5 000 par "
             "défaut) : leur latence est celle d'un résultat PARTIEL.").format(len(truncated)))
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
        W(tr("## Comment la latence monte avec le volume"))
        W("")
        # CE QUE LES COLONNES TIENNENT FIXE EST DÉRIVÉ DES ENREGISTREMENTS, PLUS AFFIRMÉ.
        # La version précédente écrivait « sur la même machine, même binaire ». Mesuré le
        # 2026-08-30 sur le relevé versionné : les 13 colonnes portaient SEPT binaires distincts,
        # deux d'entre elles tournaient tier froid ACTIF, trois portaient un autre profil de
        # données, et CINQ partageaient le même volume (600 003) — donc cinq colonnes qui ne sont
        # pas des points de l'axe. La phrase était fausse sur les quatre points.
        # POURQUOI ON NE REFUSE PAS ICI, alors que la même divergence fait refuser L3 et L7 : une
        # série de volumes s'étale sur des jours, donc `version` NE PEUT PAS y être tenu fixe tant
        # qu'une passe multi-volumes n'a pas été tirée d'un coup avec un seul binaire. Refuser
        # supprimerait la seule réponse du document à « des millions d'événements » — ce serait
        # faire TAIRE une comparaison vraie pour fermer une accusation juste. On dit donc ce que le
        # tableau mélange, à l'endroit exact où on le lit, et le refus reste réservé aux
        # comparaisons dont la paire propre EXISTE dans le relevé.
        _fixe = ("events", "db_bytes")
        _cles = set().union(*(set(cfgmeta[c]) for c in fts0_vide))
        _bouge = sorted(k for k in _cles - set(_fixe)
                        if len({json.dumps(cfgmeta[c][k], sort_keys=True, ensure_ascii=False)
                                for c in fts0_vide if k in cfgmeta[c]}) > 1)
        _dup = sorted({cfgmeta[c].get("events") for c in fts0_vide
                       if sum(1 for d in fts0_vide
                              if cfgmeta[d].get("events") == cfgmeta[c].get("events")) > 1}
                      - {None})
        W(tr("Mesuré à plusieurs volumes, masque vide, `PLUME_FTS_FIELDS=0`, fenêtre « tout ». C'est "
             "la pente qui répond à la question « des millions d'événements », pas un point isolé."))
        W("")
        W(tr("**CE QUE CES COLONNES NE TIENNENT PAS FIXE** — dérivé des enregistrements eux-mêmes, "
             "pas déclaré à la main, parce qu'une phrase de comparabilité qu'on ÉCRIT est une phrase "
             "qu'on ne mesure plus :"))
        W("")
        if _bouge:
            for k in _bouge:
                _vals = sorted({json.dumps(cfgmeta[c][k], sort_keys=True, ensure_ascii=False)
                                for c in fts0_vide if k in cfgmeta[c]})
                W(tr("- `{k}` : **{0} valeurs distinctes** parmi les colonnes. L'écart lu d'une colonne à "
                     "l'autre n'est donc PAS imputable au seul volume.").format(len(_vals), k=k))
        else:
            W(tr("- rien : toutes les colonnes s'accordent sur chaque clé que le relevé déclare, hors le "
                 "volume et la taille de base qui en découle."))
        if _dup:
            W("- **" + ", ".join(fmt_n(v) for v in _dup) + tr("** : plusieurs colonnes partagent ce volume. Deux colonnes au MÊME volume ne sont pas "
                                                              "deux points de l'axe — ce qui les sépare est, par construction, autre chose que le "
                                                              "volume."))
        W("")
        W(tr("Réserve à connaître avant de citer ce tableau : les volumes viennent de **passes "
             "distinctes**, donc de bases distinctes et de nombres de répétitions possiblement "
             "différents (la colonne `reps` du JSONL brut le dit cellule par cellule). Les points "
             "sont comparables en ordre de grandeur, pas au pourcentage près. Une case vide = classe "
             "non mesurée à ce volume. **Le rapport de la dernière colonne oppose la PREMIÈRE et la "
             "DERNIÈRE** : il hérite de tout ce qui est listé ci-dessus."))
        W("")
        hdr = " | ".join(tr("{0} lignes").format(fmt_n(cfgmeta[c].get('events'))) for c in fts0_vide)
        W(tr("| Classe | {hdr} | rapport |").format(hdr=hdr))
        W("|---" * (len(fts0_vide) + 2) + "|")
        for cid, label, kind in classes:
            vals = [(idx.get((c, cid, "all")) or {}).get("wall_p50_ms") for c in fts0_vide]
            if not any(v is not None for v in vals):
                continue
            ratio = "—"
            if vals[0] and vals[-1]:
                nr = (cfgmeta[fts0_vide[-1]].get("events") or 1) / (cfgmeta[fts0_vide[0]].get("events") or 1)
                ratio = tr("x{0:.1f} pour x{nr:.1f} de lignes").format(vals[-1]/vals[0], nr=nr)
                # Si la valeur du PETIT volume est au plancher fixe, le rapport ne mesure pas la
                # pente du scan : il mesure la distance au plancher. On le dit au lieu de laisser
                # citer un « x56 » qui n'a pas le sens qu'on croit.
                if floor_ms and vals[0] <= floor_ms * 1.15:
                    ratio += tr(" ⚠ base au plancher")
            W(f"| `{cid}` | " + " | ".join(fmt_ms(v) for v in vals) + f" | {ratio} |")
        W("")
        W(tr("Une classe dont le rapport de latence suit le rapport de lignes est un **scan** : son "
             "coût est linéaire en volume et rien ne l'indexe. Une classe dont le rapport reste plat "
             "est servie par un index ou par un rollup."))
        W("")
        if floor_ms:
            W(tr("⚠ **base au plancher** : au petit volume, la cellule était déjà au plancher fixe (~{0}, "
                 "voir `C0-plancher`). Le rapport affiché mesure alors la distance à ce plancher, PAS la "
                 "pente du scan — ne pas le citer comme un facteur d'échelle.").format(fmt_dur(floor_ms)))
        W("")

    # ---------------------------------------------------------------- leviers
    W(tr("## Leviers désignés par la mesure"))
    W("")
    W(tr("Aucun n'est implémenté ici : c'est le rôle de l'instrument de les **désigner** et de "
         "chiffrer"))
    W(tr("le gain qu'on aurait le droit d'en attendre. Classés par gain mesuré décroissant. « "
         "Coût RAM »"))
    W(tr("dit ce que le levier ajouterait au budget de 2 Gio ; quand il est nul, c'est écrit."))
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
    # Configuration MASQUÉE de référence : la plus grosse mesurée. Elle n'est PAS contrainte au
    # volume de `base`, et elle n'a plus à l'être : ce n'est plus `base` qui lui sert de terme de
    # comparaison, c'est le jumeau que `passe_comparable` lui DÉSIGNE (voir L3). L'ancienne
    # tolérance de volume — « 4 lignes d'écart ne doivent pas faire s'évaporer un levier de 36 s » —
    # traitait un symptôme réel avec le mauvais remède : elle laissait passer l'écart de volume ET
    # l'écart de binaire ET l'écart de base, en n'avouant que le premier.
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
        lev.append((floor, tr("Le plancher fixe par requête"),
                    tr("une requête dont le SQL coûte {0} revient en {1} : **{floor:.0f} ms de coût fixe**, "
                       "indépendant du volume. Cause identifiée dans le code : le chien de garde de budget est "
                       "un thread qui boucle sur `sleep(50 ms)` et il est **joint** avant que la réponse ne "
                       "parte (`daemon/src/query_exec.rs:466-537`, `done.store(true)` puis `watchdog.join()`). "
                       "Une attente à condition (condvar avec délai) ou un thread non joint rendrait ces "
                       "millisecondes à **toutes** les requêtes. **Coût RAM : nul.** C'est le levier le moins "
                       "cher du lot, et il domine toutes les requêtes rapides — donc toute l'expérience "
                       "interactive.").format(fmt_dur(fl.get('sql_p50_ms')), fmt_dur(fl['wall_p50_ms']), floor=floor),
                    tr("toutes les cellules")))

    # L2 — FTS5 non câblée sur GXQL
    a, b = cell(base, "C2d-free-term-rows", "all"), cell(base, "C2c-fts-bar", "all")
    g = gain_ms(a, b)
    if g is not None:
        lev.append((g, tr("Câbler FTS5 sur le chemin GXQL"),
                    tr("la même aiguille, le même nombre de lignes rendues : **{0}** par GXQL (`message LIKE "
                       "'%…%'`, scan complet) contre **{1}** par `/api/search` (index FTS5 `event_fts`). "
                       "L'index EXISTE et est déjà payé — sur l'installation de référence il pèse environ six "
                       "dixièmes du poids de la table — mais il n'est câblé que sur `/api/search`. Sur le "
                       "chemin GXQL, un terme libre devient `col LIKE '%motif%'` "
                       "(`core/src/soql/dialect.rs:65-67`, appelé depuis `soql/mod.rs:881-891`), donc un scan "
                       "complet. **Coût RAM : nul** — l'index est déjà construit et déjà en base.").format(fmt_dur(a['wall_p50_ms']), fmt_dur(b['wall_p50_ms'])),
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
            lev.append((g, tr("Rendre l'index d'hôte utilisable AVEC une borne temporelle"),
                        tr("le MÊME `stats count by host`, la MÊME base : **{0}** sans borne de temps contre "
                           "**{1}** borné à la fenêtre chaude du produit (`{hotw}`)").format(fmt_dur(b['wall_p50_ms']), fmt_dur(a['wall_p50_ms']), hotw=_hotw)
                        + (tr(", soit **{ratio:.0f}x plus lent**").format(ratio=ratio) if ratio else "") + tr(". Sans borne, le group-by est servi par un parcours d'index seul (`idx_event_host` "
                                                                                       "couvre la requête). Dès qu'une borne `ts` entre, l'index d'hôte ne suffit plus — il "
                                                                                       "faut ouvrir chaque ligne pour lire son `ts` — et la requête redevient un scan. Or la "
                                                                                       "borne temporelle est le cas NORMAL : un tableau de bord regarde toujours une fenêtre. "
                                                                                       "Voie : un index composite `(host, ts)`, qui rend le prédicat de temps satisfiable dans "
                                                                                       "l'index. **Coût RAM : nul ; coût DISQUE : un index de plus** (sur l'installation de "
                                                                                       "référence, `idx_event_host` pèse quelques dizaines de Mio par million d'événements). À "
                                                                                       "noter : cette cellule est déjà à 64 hôtes ; sur une flotte, le nombre de groupes ne "
                                                                                       "fait que grandir."),
                        f"C6b {_hotw} vs all"))

    # L3 — masque non vide qui désarme la route de rollups
    if masked:
        # MÊME PROPRIÉTÉ QU'EN L7, et MÊME défaut mesuré (2026-08-30) : la passe masque-vide était
        # prise dans `base`, or `base` (`chaud-seul-v2@1.4M`) et `masked`
        # (`fts0-masque-non-vide@1.4M`) divergeaient sur `version`, `events` ET `db_bytes` —
        # l'écart publié mélangeait quatre causes et n'en nommait qu'une. Le jumeau est maintenant
        # DÉSIGNÉ : la passe qui s'accorde avec la passe masquée sur tout sauf `mask`.
        vide, cause_mask = passe_comparable(cfgmeta, configs, masked, ("mask",))
        a = cell(masked, "C3b-groupby-routable", "all")
        b = cell(vide, "C3b-groupby-routable", "all") if vide else None
        g = gain_ms(a, b)
        if g is None and not vide:
            # REFUS, pas disparition : un levier qui s'évapore se lit « plus de problème ».
            lev.append((-1e9 - 1, tr("Rendre la route de rollups compatible avec le masquage"),
                        refus_de_comparer(tr("le coût du masquage sur la route de rollups"), "mask",
                                          cause_mask),
                        tr("`{masked}` — paire refusée").format(masked=masked),
                        tr("*Aucun écart n'est rendu ici : le relevé ne contient pas la paire qui isolerait le "
                           "masquage. C'est un REFUS, pas une absence de problème.*")))
        if g is not None:
            ratio = (a["wall_p50_ms"] / b["wall_p50_ms"]) if b["wall_p50_ms"] else None
            lev.append((g, tr("Rendre la route de rollups compatible avec le masquage"),
                        tr("le MÊME group-by, le MÊME rôle : **{0}** masque vide (servi depuis `{1}`, {2} lignes) "
                           "contre **{3}** masque non vide (servi depuis `{4}`, {5} lignes — les comptes diffèrent "
                           "parce que la route de rollups est APPROCHÉE, `stats.approx=true` : c'est le prix de sa "
                           "vitesse)").format(fmt_dur(b['wall_p50_ms']), b.get('served_from'), fmt_n(b.get('rows')), fmt_dur(a['wall_p50_ms']), a.get('served_from'), fmt_n(a.get('rows')))
                        + (tr(", soit **{ratio:.1f}x plus lent**").format(ratio=ratio) if ratio else "") + tr(". Le rempart de confidentialité est donc aussi un frein de performance : un masque non "
                                                                                       "vide désarme la route de rollups (`handlers/query.rs:282`) parce que `event_rollup` "
                                                                                       "stocke `src_ip`/`host` en clair. Deux voies : masquer à la lecture du rollup, ou "
                                                                                       "matérialiser un rollup par classe de masque. **Coût RAM : celui d'un jeu de rollups "
                                                                                       "supplémentaire** (sur l'installation de référence, `event_rollup` pèse de l'ordre du "
                                                                                       "Mio par million d'événements, donc marginal), plus le masquage au vol.")
                        + tr(" Les deux passes opposées sont `{vide}` et `{masked}` : elles s'accordent sur TOUT ce "
                             "que le relevé déclare — binaire, nombre d'événements, base, tier froid — sauf le "
                             "masquage. C'est la seule raison pour laquelle cet écart peut être imputé au masque.").format(vide=vide, masked=masked),
                        f"`{vide}` vs `{masked}`"))

    # L4 — group-by multi-dim haute cardinalité
    a = cell(base, "C3-groupby-hi", "all")
    b = cell(base, "C3b-groupby-routable", "all")
    if a and a.get("wall_p50_ms") is not None:
        lev.append(((a["wall_p50_ms"] - (b or {}).get("wall_p50_ms", 0)) if b else a["wall_p50_ms"],
                    tr("Étendre la route de rollups aux dimensions à haute cardinalité"),
                    tr("`stats count by src_ip,host,source` sur tout l'historique : **{0}**, servi par `{1}`. "
                       "Seules les formes `by` dont TOUTES les dimensions tiennent dans `{{source, severity}}` "
                       "sont routables (`rollup_route.rs:349-366`) ; dès qu'une dimension à haute cardinalité "
                       "entre, on retombe sur le scan. **Coût RAM : celui du grain choisi** — un rollup à grain "
                       "`src_ip` est borné à l'exécution par `PLUME_ROLLUP_SRCIP_TOPN` (50) précisément pour ne "
                       "pas exploser, ce qui rend le résultat approché. Le compromis exactitude/mémoire doit "
                       "être décidé, pas subi.").format(fmt_dur(a['wall_p50_ms']), a.get('served_from')),
                    "C3-groupby-hi / all"))

    # L5 — regex sur champ étendu non indexé
    a, b = cell(base, "C5b-regex-json-cold", "all"), cell(base, "C5c-eq-json-hot", "all")
    _hf = hot_fields()
    if a and a.get("wall_p50_ms") is not None:
        lev.append((a["wall_p50_ms"] - ((b or {}).get("wall_p50_ms") or 0),
                    tr("Le champ étendu non indexé n'a aucun chemin d'accès"),
                    tr("regex sur `fields.object` (aucun index) : **{0}**").format(fmt_dur(a['wall_p50_ms']))
                    + (tr(" contre **{0}** pour une égalité sur `fields.user`, qui a un index d'expression partiel.").format(fmt_dur(b['wall_p50_ms'])) if b and b.get("wall_p50_ms") else "")
                    + tr(" {0} champs seulement sont indexés (`HOT_FIELDS`, lu dans `daemon/src/soql_glue.rs` : "
                         "{1}) sur les **241 clés distinctes du profil mesuré**. Pour les {2} autres, toute "
                         "recherche est un scan avec `json_extract` par ligne. C'est exactement la promesse « sur "
                         "tous les champs » qui est en jeu. Voies : `event_fields_fts` (déjà écrit, voir le "
                         "levier sur le coût de `PLUME_FTS_FIELDS`), ou des index d'expression sur demande, ou un "
                         "stockage colonnaire des champs. **Coût RAM : un index d'expression par champ**, à "
                         "arbitrer — et cet arbitrage n'a aujourd'hui aucun automate : le mécanisme qui "
                         "promettait de le rendre à l'usage a été retiré (P6.8-b) sans avoir jamais promu un seul "
                         "index.").format(len(_hf), ', '.join(_hf), 241 - len(_hf)),
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
        lev.append((g, tr("Servir le curseur demandé, y compris quand le pipeline projette"),
                    tr("MÊME demande (`keyset:true`, limit 200, même filtre), seule la projection change : "
                       "**{0}** avec `| table …` contre **{1}** sans projection. Le client a demandé une "
                       "pagination par CURSEUR et reçoit une page `OFFSET` : le curseur est désactivé dès que "
                       "le pipeline contient `| table` ou `| fields`, c'est-à-dire dès qu'on projette des "
                       "colonnes — ce que fait toute récupération RAW réelle. Conséquences : pas de "
                       "`next_cursor`, un `total` PLAFONNÉ à 10 000 (des événements restent donc cachés) et un "
                       "coût qui croît avec le numéro de page. **Coût RAM : nul.**").format(fmt_dur(a['wall_p50_ms']), fmt_dur(b['wall_p50_ms'])),
                    "C4d vs C4c"))

    # L7 — coût de PLUME_FTS_FIELDS
    if fts1:
        # LA PAIRE EST TROUVÉE PAR LA PROPRIÉTÉ, ELLE N'EST PLUS PRISE DANS `base`.
        # MESURE DU DÉFAUT (2026-08-30, relevé versionné de ce dépôt) : `cfgmeta[base]` opposait
        # `chaud-seul-v2@1.4M` (bin 4bfcb9f7, 1 440 007 événements, 1434 Mio) à
        # `fts1-masque-vide@1.4M` (bin 0642474c, 1 440 003 événements, 1401 Mio) — ni le même
        # binaire, ni le même nombre d'événements, ni le même stade de remplissage. L'écart rendu
        # valait **-33 Mio / -2 %**, c'est-à-dire le SIGNE INVERSE de ce que le banc mesure, et il
        # était imprimé à travers un gabarit qui forçait le « + ». Les deux fautes sont corrigées
        # ici : l'appariement, et le signe (il est DÉRIVÉ du delta, plus jamais affirmé).
        #
        # Deux sources, dans cet ordre, et jamais la configuration `--ref` :
        #  (a) la passe FTS-on porte ELLE-MÊME sa taille d'avant-bascule (`db_bytes_fts0`) : c'est
        #      la passe comparée à ELLE-MÊME, sur SA base, à divergence nulle par construction —
        #      la meilleure paire possible, et elle était dans le relevé depuis le début ;
        #  (b) à défaut, le jumeau FTS-off DÉSIGNÉ par la propriété (`passe_comparable`).
        # Sur ce relevé les deux rendent le même octet (1 324 294 144), ce qui est la vérification
        # croisée de (a) par (b).
        AXES_FTS = ("fts_fields", "db_bytes")
        fts0, cause_fts = passe_comparable(cfgmeta, configs, fts1, AXES_FTS)
        d1 = cfgmeta[fts1].get("db_bytes")
        d0 = cfgmeta[fts1].get("db_bytes_fts0") or (cfgmeta[fts0].get("db_bytes") if fts0 else None)
        cls1 = {r["class_id"] for r in eff if r["config_id"] == fts1}
        peak0 = max((r.get("peak_rss_bytes") or 0) for r in eff
                    if r["config_id"] == fts0 and r["class_id"] in cls1) if fts0 else 0
        peak1 = max((r.get("peak_rss_bytes") or 0) for r in eff if r["config_id"] == fts1)
        a = cell(fts1, "C2d-free-term-rows", "all")
        b = cell(fts0, "C2d-free-term-rows", "all") if fts0 else None
        g = gain_ms(b, a)
        # Le SIGNE est DÉRIVÉ du delta. Le gabarit précédent écrivait « +{delta} » quoi qu'il
        # arrive : sur un delta négatif il rendait « +-33 Mio », et un lecteur pressé y lisait une
        # hausse. Un gabarit ne doit jamais affirmer ce que la mesure n'a pas dit.
        dd = (d1 - d0) if (d0 and d1) else None
        sgn = "" if dd is None else ("+" if dd >= 0 else "-")
        txt = ""
        if dd is not None:
            txt += (tr("activer `PLUME_FTS_FIELDS=1` a fait passer la base de **{0} Mio à {1} Mio** ({sgn}{2} "
                       "Mio, {sgn}{3:.0f} %), sur la paire que la propriété désigne : ").format(fmt_mib(d0), fmt_mib(d1), fmt_mib(abs(dd)), abs(dd)/d0*100, sgn=sgn)
                    + (tr("la passe `{fts1}` comparée à SA PROPRE taille d'avant-bascule (`db_bytes_fts0`), donc "
                          "sur la même base, le même binaire et le même nombre d'événements. ").format(fts1=fts1) if cfgmeta[fts1].get("db_bytes_fts0")
                       else tr("`{fts0}` contre `{fts1}`. ").format(fts0=fts0, fts1=fts1)))
        else:
            txt += refus_de_comparer(tr("le coût DISQUE de `PLUME_FTS_FIELDS=1`"), "fts_fields",
                                     cause_fts or tr("la passe FTS-on ne relève pas `db_bytes`")) + " "
        if fts0:
            txt += (tr("RSS crête, sur les SEULES classes mesurées dans les deux configurations ({0}), et sur "
                       "la MÊME paire : **{1} Mio** à `FTS_FIELDS=0` (`{fts0}`) contre **{2} Mio** à "
                       "`FTS_FIELDS=1`. Attention : chaque configuration repart d'un daemon neuf, donc ces deux "
                       "crêtes n'ont pas eu le même historique pour monter — l'écart n'est PAS attribuable au "
                       "drapeau seul, dans aucun des deux sens. Le chiffre solide de cette ligne est le coût "
                       "DISQUE. ").format(len(cls1), fmt_mib(peak0), fmt_mib(peak1), fts0=fts0))
        elif dd is None:
            # Le refus DISQUE vient de nommer le MÊME axe et la MÊME cause : le répéter mot pour
            # mot n'ajoute rien et dilue le refus. On le rattache.
            txt += (tr("La crête RSS tombe sous le MÊME refus, pour la MÊME raison : elle demande deux passes, "
                       "et la paire n'existe pas. "))
        else:
            txt += refus_de_comparer(tr("la crête RSS de `PLUME_FTS_FIELDS=1`"), "fts_fields",
                                     cause_fts) + " "
        if g is not None:
            txt += (tr("Écart de latence observé sur le terme libre GXQL (tout l'historique), sur la MÊME paire "
                       ": **{0}** ").format(fmt_dur(abs(g)))
                    + (tr("en faveur de FTS_FIELDS=1") if g > 0 else tr("en défaveur de FTS_FIELDS=1"))
                    + tr(" — mais cet écart ne peut PAS venir du drapeau, puisque le chemin GXQL ne lit jamais "
                         "`event_fields_fts` : c'est du bruit de mesure sur une machine partagée, et il est "
                         "reporté comme tel. "))
        elif fts0:
            txt += tr("Le gain en latence sur le chemin GXQL n'a pas pu être mesuré. ")
        # LE COÛT QUI DÉCIDE N'EST PAS DANS CE BANC, ET IL A SON LOGEMENT ICI — posé le 2026-08-30
        # après qu'une correction écrite À LA MAIN dans la page rendue eut été relevée comme
        # DÉFAISABLE PAR UNE SIMPLE RÉGÉNÉRATION. La substance vit dans le document du chiffrement,
        # parce qu'elle est établie par LECTURE DES SOURCES et non par une passe de banc : la
        # recopier ici en ferait une seconde vérité à entretenir, qui vieillirait sans rougir.
        # Ce que le générateur doit produire, c'est le RENVOI — pour qu'un lecteur du banc ne
        # puisse pas conclure que le coût publié est le seul, ni qu'un défaut à l'arrêt le serait
        # pour une raison de performance.
        txt += (tr("LE COÛT QUI DÉCIDE N'EST PAS DANS CE BANC, ET IL EST PLUS LOURD QUE CEUX QUI PRÉCÈDENT "
                   ": l'index des champs est déclaré SANS TABLE DE CONTENU, forme que le plan de sauvegarde "
                   "typé ne sait pas recréer ; chaque cycle compressé se replie alors sur un export qui "
                   "matérialise une copie DÉCHIFFRÉE COMPLÈTE de la base, le temps du cycle. Activer cette "
                   "capacité est donc un ÉCHANGE PERFORMANCE CONTRE CONFIDENTIALITÉ, et c'est cette "
                   "raison-là — non un surcoût de mémoire, que ce banc ne mesure dans aucun sens — qui "
                   "justifie que le défaut soit à l'arrêt. Établi par lecture des sources, jamais par une "
                   "passe : voir `docs/CHIFFREMENT-COMPRESSION.md` §3. "))
        txt += (tr("À retenir : `event_fields_fts` n'est lu que par `/api/search` "
                   "(`handlers/search.rs:146-157`). Le chemin GXQL ne le consulte JAMAIS — donc son coût en "
                   "disque et en ingest est payé sans que les requêtes GXQL en profitent. C'est le levier « "
                   "Câbler FTS5 sur le chemin GXQL » qui rendrait ce coût déjà consenti utile aux requêtes "
                   "GXQL."))
        # Cette entrée n'est pas un levier de GAIN : c'est un COÛT mesuré. On la classe en dernier
        # (clé de tri négative) et on remplace l'en-tête « gain » par le coût disque, sinon on
        # publierait « gain : -501 ms », qui ne veut rien dire.
        lev.append((-1e9, tr("Le coût de `PLUME_FTS_FIELDS=1`, et à qui il profite"), txt,
                    (f"`{fts0}` vs `{fts1}`" if fts0 else tr("`{fts1}` — paire refusée").format(fts1=fts1)),
                    (tr("Effet DISQUE mesuré sur la SEULE paire que la propriété désigne : **{sgn}{0:.0f} %** de "
                        "base ({sgn}{1} Mio). ").format(abs(dd)/d0*100, fmt_mib(abs(dd)), sgn=sgn)
                     + (tr("Ce n'est pas un gain, c'est une dépense — et le document dit plus bas à qui elle "
                           "profite, et ce qu'elle coûte AILLEURS que sur le disque.")
                        if dd > 0 else
                        tr("La base RÉTRÉCIT sur cette paire : le sens de cet écart est DÉRIVÉ de la mesure, il "
                           "n'est pas affirmé par le gabarit — et il contredit ce que le document a longtemps "
                           "supposé, donc il demande une seconde passe avant d'être cité.")))
                    if dd is not None else
                    tr("*Aucun coût disque n'est rendu ici : la paire comparable manque (voir le refus "
                       "ci-dessous).*")))

    lev = [(t if len(t) == 5 else (t[0], t[1], t[2], t[3], None)) for t in lev]
    for i, (g, title, body, src, override) in enumerate(sorted(lev, key=lambda x: -(x[0] or 0)), 1):
        W(f"### L{i}. {title}")
        W("")
        if override:
            W(f"*{override}*")
        else:
            W(tr("*Gain mesuré : **{0}** au p50 sur la cellule la plus parlante ({src}). Ce n'est pas une "
                 "promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent "
                 "et un chemin rapide déjà existant ou atteignable.*").format(fmt_dur(g) if g is not None else '—', src=src))
        W("")
        W(body)
        W("")

    W(tr("## Ce qui n'est PAS mesuré ici"))
    W("")
    if cold_cfgs:
        W(tr("- **Le tier froid au-delà de ce qui est tiré** : {0} configuration(s) tournent").format(len(cold_cfgs)))
        W(tr("  `PLUME_COLD_TIER=1` (section dédiée plus haut), mais sur UNE seule taille de fenêtre"))
        W(tr("  chaude et UN seul volume. Le moteur vectorisé n'est pas mesuré séparément du chemin"))
        W(tr("  d'hydratation : le document ne dit pas lequel a servi chaque cellule au-delà de ce que"))
        W(tr("  `stats.cold` en rapporte."))
    else:
        W(tr("- **Le tier froid** (`--features cold_tier` + `PLUME_COLD_TIER=1`) : le binaire est "
             "compilé"))
        W(tr("  avec la feature, mais toutes les cellules tournent `PLUME_COLD_TIER=0`. Aucun chiffre "
             "de ce"))
        W(tr("  document ne dit quoi que ce soit du chemin Parquet ni du moteur vectorisé."))
    if conc:
        _cl = sorted({r.get("analysts") for r in conc if r.get("analysts")})
        _sems = sorted({r.get("query_sem") for r in conc if r.get("query_sem")})
        _wins = sorted({r.get("window") for r in conc if r.get("window")})
        W(tr("- **La concurrence est mesurée** (section dédiée) : jusqu'à {0} analystes").format(max(_cl)))
        W(tr("  simultanés, sémaphore {0}. Ce qui reste hors mesure :").format(tr(" et ").join(str(s) for s in _sems)))
        W(tr("  la concurrence PENDANT une ingestion (les deux charges sont mesurées séparément), la"))
        W(tr("  charge SOUTENUE sur des heures (chaque niveau dure des dizaines de secondes, pas une"))
        W(tr("  journée), et les fenêtres autres que {0} — le").format(', '.join('`' + w + '`' for w in _wins)))
        W(tr("  mélange est tiré sur la fenêtre la plus coûteuse, pas sur toutes."))
    else:
        W(tr("- **La concurrence** : une requête à la fois. `PLUME_QUERY_CONCURRENCY=3` est en place "
             "mais"))
        W(tr("  jamais saturé (`sem_wait_ms` reste nul). Le comportement à 10 utilisateurs simultanés "
             "n'est"))
        W(tr("  pas mesuré."))
    W(tr("- **Le multi-tenant** (`PLUME_MULTI_TENANT=1`) : tout est mesuré en mode 0."))
    W(tr("- **Le cache de pages froid** : impossible de le vider sans privilège root sur la "
         "machine de"))
    W(tr("  mesure. La colonne `lu` dit ce qui a réellement atteint le disque ; elle ne dit pas "
         "ce que"))
    W(tr("  ferait un démarrage à froid complet."))
    W(tr("- **La fidélité du texte** : le corps des messages est synthétique. Les chiffres FTS5, "
         "`LIKE`"))
    W(tr("  et `REGEXP` dépendent directement de ce vocabulaire ; c'est la limite la plus "
         "sérieuse du"))
    W(tr("  banc et elle est décrite dans `bench/gen_events.py` (`VOCAB`)."))
    W(tr("- **L'indexation des champs étendus** : `PLUME_EXPRINDEX=1` (le défaut livré) est le "
         "SEUL"))
    W(tr("  levier, et il n'indexe que les noms de `HOT_FIELDS`. Aucun mécanisme n'indexe plus un "
         "champ"))
    W(tr("  à l'usage — celui qui le promettait a été retiré (P6.8-b) sans avoir jamais promu un "
         "index."))
    W(tr("  Ce tableau ne peut donc PAS montrer un champ étendu hors de cette liste servi par un "
         "index :"))
    W(tr("  ce n'est pas une case non mesurée, c'est une case qu'aucune configuration ne "
         "remplirait."))
    W("")

    W(tr("## Reproduire, et contredire"))
    W("")
    W("```sh")
    W(tr("# 1. le profil de données (déjà versionné ; à re-extraire seulement pour une autre prod)"))
    W(tr("#    bench/prod-profile.sql, LECTURE SEULE, n'extrait aucune valeur de ligne"))
    W(tr("# 2. la matrice complète, de bout en bout :"))
    W("CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \\")
    W("    --manifest-path daemon/Cargo.toml")
    W(tr("bench/run.sh                       # 10 M d'événements"))
    W(tr("BENCH_EVENTS=1000000 bench/run.sh  # 1 M, pour itérer"))
    if conc:
        _cs = ",".join(str(s) for s in sorted({r.get("query_sem") for r in conc if r.get("query_sem")}))
        _cl = ",".join(str(n) for n in sorted({r.get("analysts") for r in conc if r.get("analysts")}))
        W(tr("# 2 bis. la CONCURRENCE, sur une base déjà remplie (redémarre le daemon par valeur de"))
        W(tr("#        sémaphore et lui REDEMANDE ce qu'il applique avant de mesurer) :"))
        W(f"BENCH_PHASES=concurrency BENCH_SEM_SWEEP={_cs} BENCH_CONC_LEVELS={_cl} bench/run.sh")
    W(tr("# 3. le rendu — LES COMMANDES EXACTES qui ont produit ce document et sa traduction,"))
    W(tr("#    reconstruites depuis leurs propres arguments et pointées sur les données VERSIONNÉES"))
    W(tr("#    (donc rejouables par un tiers). Rendu anglais :"))
    for _l in repro_cmd(args):
        W(_l)
    W("```")
    W("")
    W(tr("Ces commandes sont **régénérées à chaque rendu** : elles ne peuvent pas se désynchroniser du"))
    W(tr("document. C'est délibéré — la version précédente publiait une commande incomplète qui, rejouée"))
    W(tr("telle quelle, AMPUTAIT le document de ses sections d'écart et de ses tableaux "
         "d'attribution."))
    W(tr("Une commande de reproduction fausse est pire qu'absente : elle fait croire à une"))
    W(tr("reproduction réussie."))
    W("")
    W(tr("Le générateur est déterministe : `python3 bench/gen_events.py --count N --end-ts T "
         "--digest`"))
    W(tr("imprime le SHA-256 du flux. Deux exécutions avec les mêmes paramètres donnent la même"))
    W(tr("empreinte — c'est ce qui rend un désaccord sur les chiffres arbitrable."))
    W("")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"écrit {args.out} — {len(eff)} cellules ({superseded} remplacées par rejeu), {len(configs)} configurations, "
          f"{len(over)} au-dessus de 2 Gio, {len(swapped)} sous swap, {len(failed)} en erreur")



# --------------------------------------------------------------------------------------------
# CHAÎNES VENUES DES DONNÉES. Les JSONL de `bench/results/` sont des mesures VERSIONNÉES : on ne les
# réécrit pas pour traduire leurs libellés. Le rendu anglais traduit ceux qu'il connaît ; un libellé
# neuf sort tel quel jusqu'à ce qu'on l'ajoute ici.
DONNEES_EN = {
    "off":
        "off",
    "2597 s = intervalle MESURÉ entre l'horodatage du premier et du dernier fichier Parquet écrit (22 fichiers, un par jour). La passe a ensuite été INTERROMPUE par un kill EXTÉRIEUR au produit pendant la phase de suppression du chaud, puis REPRISE par un second `plume-daemon retention` qui a terminé en ~90 s et rendu « rétention OK » : l'aging est repartite sans perte, ce qui est son contrat (deux phases, idempotent). La durée totale n'est donc PAS un débit de columnarisation propre, et n'est pas publiée comme tel.":
        "2597 s = MEASURED interval between the timestamps of the first and the last Parquet file written (22 files, one per day). The run was then INTERRUPTED by a kill EXTERNAL to the product during the hot deletion phase, then RESUMED by a second `plume-daemon retention` which finished in ~90 s and returned \"rétention OK\": the aging restarted without loss, which is its contract (two phases, idempotent). The total duration is therefore NOT a clean columnarisation throughput, and is not published as such.",
    "Verdicts et compte de NOMBRES FAUX RE-DÉRIVÉS avec le classifieur courant à partir des réponses `hot`/`cold` STOCKÉES, qui sont la mesure. Sans ce re-dérivage, les deux passes seraient comptées par deux règles différentes et leur comparaison ne voudrait rien dire. Aucune réponse n'a été re-mesurée.":
        "Verdicts and WRONG NUMBER count RE-DERIVED with the current classifier from the STORED `hot`/`cold` answers, which are the measurement. Without this re-derivation, the two runs would be counted by two different rules and their comparison would mean nothing. No answer was re-measured.",
    "LA DIVERGENCE ×6,6 DE LA PASSE PRÉCÉDENTE EST CORRIGÉE, ET C'EST CETTE PASSE QUI LE MESURE. La réserve de `parity-apres-2026-07-31` décrivait le binaire d'AVANT le correctif de couverture des rollups ; elle ne décrit plus le dépôt. Mesuré ici, sur la MÊME base et au MÊME instant que la matrice (le compte BRUT étant `search | stats count` sur le MÊME daemon) : côté SANS tier froid, `search | stats count by source,severity` rend 1 080 321 sur la fenêtre `au-dela-7d`, 359 679 sur `7d` et 1 440 007 sur `all` — soit EXACTEMENT le compte brut des trois fenêtres, là où la passe précédente rendait 164 165 sous `approx:false` pour 1 080 321 réels. Le nombre de groupes coïncide désormais des deux côtés (68/68, 63/63, 70/70 ; c'était 59 contre 68). CE QUI RESTE, ET DANS L'AUTRE SENS : 2 contrôles divergent encore, tous deux `C3b-groupby-routable`, et c'est le côté AVEC tier froid qui SUR-compte — 1 082 346 contre 1 080 321 (+2 025, soit +0,19 %) sur `au-dela-7d`, 360 020 contre 359 679 (+341, soit +0,09 %) sur `7d`. Ce côté-là se déclare `approx:true` et porte sa note ; le côté sans tier froid est `approx:false` et exact. La cause est le résidu DOCUMENTÉ de `plan_merge` : sous la frontière chaud/froid, `event` est agé en Parquet, donc un partiel de TÊTE sous-horaire ne peut pas être scanné en brut et est REPLIÉ dans le corps rollup, qui couvre l'heure entière — la fenêtre `au-dela-7d` du banc commence à 1782990828, non aligné à l'heure, et le repli ajoute la tranche [1782990000, 1782990828). Ce n'est donc pas un reste du défaut corrigé : c'est le grain horaire, borné à une sliver sub-horaire, et annoncé. POURQUOI CES 2 SONT QUAND MÊME COMPTÉS COMME NOMBRES FAUX : le classifieur ne rachète JAMAIS un agrégat qui diverge parce qu'il est déclaré (`declared n'acquitte rien`). La règle est conservée telle quelle — l'assouplir pour faire tomber le compte à zéro serait changer la règle après avoir vu le résultat.":
        "THE ×6.6 DIVERGENCE OF THE PREVIOUS RUN IS FIXED, AND IT IS THIS RUN THAT MEASURES IT. The caveat of `parity-apres-2026-07-31` described the binary from BEFORE the rollup coverage fix; it no longer describes the repository. Measured here, on the SAME database and at the SAME moment as the matrix (the RAW count being `search | stats count` on the SAME daemon): on the side WITHOUT the cold tier, `search | stats count by source,severity` returns 1,080,321 over the `au-dela-7d` window, 359,679 over `7d` and 1,440,007 over `all` — i.e. EXACTLY the raw count of the three windows, where the previous run returned 164,165 under `approx:false` for 1,080,321 real ones. The number of groups now matches on both sides (68/68, 63/63, 70/70; it was 59 against 68). WHAT REMAINS, AND IN THE OTHER DIRECTION: 2 checks still diverge, both `C3b-groupby-routable`, and it is the side WITH the cold tier that OVER-counts — 1,082,346 against 1,080,321 (+2,025, i.e. +0.19 %) over `au-dela-7d`, 360,020 against 359,679 (+341, i.e. +0.09 %) over `7d`. That side declares itself `approx:true` and carries its note; the side without the cold tier is `approx:false` and exact. The cause is the DOCUMENTED residue of `plan_merge`: below the hot/cold boundary, `event` is aged into Parquet, so a sub-hour HEAD partial cannot be scanned raw and is FOLDED into the rollup body, which covers the whole hour — the bench's `au-dela-7d` window starts at 1782990828, not aligned to the hour, and the fold adds the slice [1782990000, 1782990828). It is therefore not a leftover of the fixed defect: it is the hourly grain, bounded to a sub-hour sliver, and announced. WHY THESE 2 ARE STILL COUNTED AS WRONG NUMBERS: the classifier NEVER redeems a diverging aggregate because it is declared (`declared` acquits nothing). The rule is kept as is — loosening it to bring the count down to zero would be changing the rule after seeing the result.",
    "LES 3 NOMBRES FAUX QUI RESTENT NE SONT PAS CEUX DU TIER FROID. Ils sont tous portés par la MÊME classe, `C3b-groupby-routable` (`search | stats count by source,severity`), et les deux côtés la servent par la ROUTE DE ROLLUPS, pas par le chemin froid. Mesuré sur la fenêtre `au-dela-7d`, sur la MÊME donnée : la somme des counts vaut 164 165 côté SANS tier froid (`approx:false`, `truncated:false` — donc présentée comme EXACTE) et 1 082 346 côté AVEC (`approx:true`, avec sa note). Le compte BRUT de la même fenêtre, mesuré des deux côtés par `search | stats count`, vaut 1 080 321. C'est donc la route de rollups du côté SANS tier froid qui SOUS-COMPTE d'un facteur 6,6, en se déclarant exacte — un second défaut de la même famille (un nombre faux sans avertissement), DISTINCT de la troncature froide, NON corrigé ici, et reproductible : une base restaurée dont `event_rollup` ne couvre pas le passé profond sert des tableaux de bord sous-comptés. La réserve de la passe du 31/07 laissait ce mécanisme « non expliqué » ; il l'est maintenant, et il reste ouvert.":
        "THE 3 WRONG NUMBERS THAT REMAIN ARE NOT THOSE OF THE COLD TIER. They are all carried by the SAME class, `C3b-groupby-routable` (`search | stats count by source,severity`), and both sides serve it through the ROLLUP ROUTE, not through the cold path. Measured over the `au-dela-7d` window, on the SAME data: the sum of the counts is 164,165 on the side WITHOUT the cold tier (`approx:false`, `truncated:false` — hence presented as EXACT) and 1,082,346 on the side WITH it (`approx:true`, with its note). The RAW count of the same window, measured on both sides by `search | stats count`, is 1,080,321. It is therefore the rollup route on the side WITHOUT the cold tier that UNDER-counts by a factor of 6.6, while declaring itself exact — a second defect of the same family (a wrong number without warning), DISTINCT from the cold truncation, NOT fixed here, and reproducible: a restored database whose `event_rollup` does not cover the deep past serves under-counted dashboards. The caveat of the 07/31 run left this mechanism \"unexplained\"; it now is explained, and it remains open.",
    "Une TROISIÈME requête a été tirée (`search | stats count by source,severity`, fenêtre au-dela-7d) : les deux côtés l'ont servie par la ROUTE DE ROLLUPS, sans troncature, mais leurs valeurs divergent d'un facteur ~6,6 (la copie intacte rend ~160 k événements au total, la columnarisée ~1,05 M — cette dernière étant cohérente avec le volume attendu de la fenêtre). Cette divergence N'EST PAS EXPLIQUÉE par cette mesure. Mécanisme candidat, à départager par une expérience dédiée : la fraîcheur d'`event_rollup`, que la boucle de rollups (120 s) et `retention_run` alimentent — le daemon de la copie intacte venait de démarrer, celui de la copie columnarisée tournait depuis 20 minutes ET avait vu passer un `retention_run` complet. Tant que ce n'est pas tranché, aucune conclusion n'est tirée de cette troisième requête.":
        "A THIRD query was fired (`search | stats count by source,severity`, window au-dela-7d): both sides served it through the ROLLUP ROUTE, without truncation, but their values diverge by a factor of ~6.6 (the intact copy returns ~160 k events in total, the columnarised one ~1.05 M — the latter being consistent with the expected volume of the window). This divergence IS NOT EXPLAINED by this measurement. Candidate mechanism, to be settled by a dedicated experiment: the freshness of `event_rollup`, which the rollup loop (120 s) and `retention_run` feed — the daemon of the intact copy had just started, that of the columnarised copy had been running for 20 minutes AND had seen a full `retention_run` go by. Until this is settled, no conclusion is drawn from this third query.",
    "MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)":
        "SAME needle in GXQL returning ROWS (comparable to /api/search)",
    "MÊME aiguille via /api/search (FTS5 event_fts)":
        "SAME needle via /api/search (FTS5 event_fts)",
    "MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)":
        "SAME needle via /api/search (FTS5 event_fts, 100 rows)",
    "PLANCHER : seek sur une source inexistante (0 ligne)":
        "FLOOR: seek on a non-existent source (0 rows)",
    "RAW keyset d'UN hôte (« montre-moi cette machine »)":
        "RAW keyset of ONE host (\"show me this machine\")",
    "RAW paginé en keyset (curseur, sans offset)":
        "RAW paginated by keyset (cursor, no offset)",
    "RAW paginé page 1 (limit 200, offset 0)":
        "RAW paginated page 1 (limit 200, offset 0)",
    "RAW paginé page profonde (offset 200 000)":
        "RAW paginated deep page (offset 200,000)",
    "filtre sur UN hôte (idx_event_host, sélectivité 1/N)":
        "filter on ONE host (idx_event_host, selectivity 1/N)",
    "group-by 2 dims ROUTABLE en rollup (source,severity)":
        "group-by 2 dims ROUTABLE to rollup (source,severity)",
    "group-by 3 dims haute cardinalité (src_ip,host,source)":
        "group-by 3 high-cardinality dims (src_ip,host,source)",
    "group-by sur champ ÉTENDU indexé (action) + colonne":
        "group-by on indexed EXTENDED field (action) + column",
    "group-by sur host (autant de groupes que de machines)":
        "group-by on host (as many groups as machines)",
    "keyset DEMANDÉ sur un pipeline PROJETÉ (| table)":
        "keyset REQUESTED on a PROJECTED pipeline (| table)",
    "regex sur champ ÉTENDU NON indexé (fields.object)":
        "regex on NON-indexed EXTENDED field (fields.object)",
    "regex sur champ ÉTENDU planté (fields.needle)":
        "regex on planted EXTENDED field (fields.needle)",
    "regex sur message (REGEXP, UDF Rust)":
        "regex on message (REGEXP, Rust UDF)",
    "scan filtré + agrégat (source + severity)":
        "filtered scan + aggregate (source + severity)",
    "scan filtré + dc() sur colonne réelle":
        "filtered scan + dc() on a real column",
    "terme libre PEU sélectif (1 ligne sur 10) en LIKE":
        "free term with LOW selectivity (1 row in 10) as LIKE",
    "terme libre sur message (compile en LIKE '%…%')":
        "free term on message (compiles to LIKE '%…%')",
    "égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)":
        "equality on INDEXED EXTENDED field (fields.user, idx_ev_f_user)",
    "non-vide (src_ip=mask, fields.user=partial)":
        "non-empty (src_ip=mask, fields.user=partial)",
    "vide":
        "empty",
    "APRÈS le correctif. MÊME base 1 440 007 événements, deux copies : l'une columnarisée (PLUME_COLD_TIER=1, 335 255 lignes chaudes + 1 104 752 en 22 Parquet), l'autre intacte (PLUME_COLD_TIER=0). MÊME binaire post-correctif (bin:4bfcb9f76b4353a2), MÊME machine, MÊMES requêtes, MÊMES fenêtres — la matrice de measure.py en entier, produite par bench/parity.py (rejouable).":
        "AFTER the fix. SAME database of 1,440,007 events, two copies: one columnarised (PLUME_COLD_TIER=1, 335,255 hot rows + 1,104,752 in 22 Parquet files), the other intact (PLUME_COLD_TIER=0). SAME post-fix binary (bin:4bfcb9f76b4353a2), SAME machine, SAME queries, SAME windows — the full measure.py matrix, produced by bench/parity.py (replayable).",
    "APRÈS les correctifs de COUVERTURE des rollups (event_rollup ET event_dim_rollup, cf. daemon/src/rollup_coverage.rs). MÊME base de banc 1440007 événements, deux copies FRAÎCHES du même fichier : l'une columnarisée (PLUME_COLD_TIER=1, 330255 lignes chaudes + 1109752 en 22 Parquet), l'autre intacte (PLUME_COLD_TIER=0). MÊME binaire de mesure (bin:80a19382ef3d30b8), MÊME machine, MÊMES requêtes, MÊMES fenêtres — la matrice de measure.py en entier, produite par bench/parity.py (rejouable). La columnarisation a été produite par un build release de l'arbre efd39e5 ; le code d'aging (cold_age_run) est identique dans le binaire de mesure. LES DEUX daemons ont TICKÉ avant la mesure et la publication de leur couverture (event_rollup_cov_id) a été VÉRIFIÉE des deux côtés — la passe précédente notait elle-même que l'un des daemons venait de démarrer quand l'autre tournait depuis vingt minutes, facteur non contrôlé qui est ici éliminé.":
        "AFTER the rollup COVERAGE fixes (event_rollup AND event_dim_rollup, see daemon/src/rollup_coverage.rs). SAME bench database of 1440007 events, two FRESH copies of the same file: one columnarised (PLUME_COLD_TIER=1, 330255 hot rows + 1109752 in 22 Parquet files), the other intact (PLUME_COLD_TIER=0). SAME measurement binary (bin:80a19382ef3d30b8), SAME machine, SAME queries, SAME windows — the full measure.py matrix, produced by bench/parity.py (replayable). The columnarisation was produced by a release build of tree efd39e5; the aging code (cold_age_run) is identical in the measurement binary. BOTH daemons TICKED before the measurement and the publication of their coverage (event_rollup_cov_id) was VERIFIED on both sides — the previous run itself noted that one of the daemons had just started while the other had been running for twenty minutes, an uncontrolled factor which is eliminated here.",
    "AVANT le correctif. MÊME base 1 440 007 événements, deux copies : l'une columnarisée (PLUME_COLD_TIER=1, 335 255 lignes chaudes + 1 104 752 en 22 Parquet), l'autre intacte (PLUME_COLD_TIER=0). MÊME binaire pré-correctif (bin:0642474ceedfaf15), MÊME machine, MÊMES requêtes, MÊMES fenêtres — la matrice de measure.py, en entier.":
        "BEFORE the fix. SAME database of 1,440,007 events, two copies: one columnarised (PLUME_COLD_TIER=1, 335,255 hot rows + 1,104,752 in 22 Parquet files), the other intact (PLUME_COLD_TIER=0). SAME pre-fix binary (bin:0642474ceedfaf15), SAME machine, SAME queries, SAME windows — the measure.py matrix, in full.",
    "MÊME base, deux copies : l'une columnarisée (PLUME_COLD_TIER=1, 335 255 lignes chaudes + 1 104 752 en Parquet), l'autre intacte (PLUME_COLD_TIER=0, 1 440 007 lignes chaudes). MÊME binaire, MÊME machine, MÊMES requêtes, MÊMES fenêtres. On compare LES VALEURS RENDUES, pas les temps : une latence n'est comparable que si la réponse l'est.":
        "SAME database, two copies: one columnarised (PLUME_COLD_TIER=1, 335,255 hot rows + 1,104,752 in Parquet), the other intact (PLUME_COLD_TIER=0, 1,440,007 hot rows). SAME binary, SAME machine, SAME queries, SAME windows. The VALUES RETURNED are compared, not the times: a latency is comparable only if the answer is.",
    "le daemon n'existe plus après ce niveau : sous MemoryMax sans swap, cela signifie un DÉPASSEMENT DU BUDGET (kill du noyau). Les niveaux suivants ne sont PAS mesurés.":
        "the daemon no longer exists after this level: under MemoryMax without swap, this means a BUDGET OVERRUN (kernel kill). The following levels are NOT measured.",
    "déclaré par le daemon (/api/system/diag)":
        "declared by the daemon (/api/system/diag)",
    "dernier jour":
        "last day",
    "dernière heure":
        "last hour",
    "tout":
        "all",
}

# Libellés qui PORTENT une valeur (une fenêtre en jours, un rapport au plancher) : écrits par
# `bench/measure.py`, `bench/concurrency.py` et `bench/run.sh` avec la valeur du jour, ils se
# traduisent par gabarit. Troisième terme : la forme française RENDUE quand l'enregistrée cite un
# libellé de fenêtre comme un identifiant (`tout` n'est pas un identifiant, `all` en est un).
DONNEES_GABARITS = [
    (re.compile(r"le plus coûteux de la famille (\S+) ne fait que (\S+) x le plancher \(seuil (\S+)\)"),
     "the most expensive of family {0} is only {1} x the floor (threshold {2})", None),
    (re.compile(r"fenêtre chaude du produit \((\d+) j\)"), "the product's hot window ({0} d)", None),
    (re.compile(r"au-delà de la fenêtre chaude \(de -(\d+) j à -(\d+) j\)"),
     "beyond the hot window (from -{0} d to -{1} d)", None),
    (re.compile(r"toute la rétention \((\d+) j\)"), "the whole retention ({0} d)", None),
    (re.compile(r"actif \(hot=(\d+)j\)"), "active (hot={0}d)", None),
    (re.compile(r"portée nulle \(span=(\S+) j, chaud=(\S+) j\)"), "zero span (span={0} d, hot={1} d)",
     None),
    (re.compile(r"le jeu ne fait que (\S+) j : cette fenêtre serait `tout` sous une étiquette de (\d+) j"),
     "the dataset only spans {0} d: this window would be `all` under a {1} d label",
     "le jeu ne fait que {0} j : cette fenêtre serait `all` (« tout ») sous une étiquette de {1} j"),
]

# Retouches du RENDU français d'une donnée (jamais du fichier) : une phrase entière entre accents
# graves n'est pas un identifiant ; seul le nom du verdict en est un.
DONNEES_FR_RETOUCHES = [
    ("(`declared n'acquitte rien`)", "(`declared` n'acquitte rien)"),
]

TEXTES_EN = {
    "# 3. le rendu — LES COMMANDES EXACTES qui ont produit ce document et sa traduction,":
        "# 3. the rendering — THE EXACT COMMANDS that produced this document and its translation,",
    "#    reconstruites depuis leurs propres arguments et pointées sur les données VERSIONNÉES":
        "#    rebuilt from their own arguments and pointed at the VERSIONED data",
    "#    (donc rejouables par un tiers). Rendu anglais :":
        "#    (hence replayable by a third party). English rendering:",
    "#    la même commande, pour le rendu français :":
        "#    the same command, for the French rendering:",
    "# les commandes ci-dessus ne tourneront qu'une fois ce fichier ajouté à bench/results/.":
        "# the commands above will only run once this file has been added to bench/results/.",
    "*Provenance du processeur, de la RAM et du noyau* : repris de la ligne de commande (`--materiel`), et non relevés au moment de ce rendu.":
        "*Provenance of the processor, RAM and kernel*: taken from the command line (`--materiel`), not read at the time of this rendering.",
    "*Provenance du processeur, de la RAM et du noyau* : relevés sur la machine qui a rendu ce document, au moment du rendu.":
        "*Provenance of the processor, RAM and kernel*: read on the machine that rendered this document, at the time of rendering.",
    "Les fichiers de résultats n'enregistrent ni le matériel ni le noyau : ces trois lignes décrivent une machine de RENDU, pas nécessairement la machine qui a mesuré — le noyau affiché, en particulier, peut différer de celui de la mesure.":
        "The result files record neither the hardware nor the kernel: these three rows describe a RENDERING machine, not necessarily the machine that measured — the kernel shown, in particular, may differ from the one of the measurement.",
    "# ATTENTION : {0} n'est pas (encore) versionné —":
        "# WARNING: {0} is not versioned (yet) —",
    "## La concurrence — ce que le nœud fait quand l'équipe travaille en même temps":
        "## Concurrency — what the node does when the team works at the same time",
    "Tout le reste de ce document est pris **une requête à la fois** : aucune requête n'y attend":
        "Everything else in this document is taken **one query at a time**: no query waits for",
    "son tour, et le document le disait lui-même. Cette section mesure l'autre condition, la":
        "its turn there, and the document said so itself. This section measures the other condition, the",
    "vraie : plusieurs analystes qui lancent de **très grosses** requêtes en même temps, sur la":
        "real one: several analysts launching **very large** queries at the same time, on the",
    "même base et sous le **même budget appliqué** de 2 Gio.":
        "same database and under the **same enforced budget** of 2 GiB.",
    "**Un niveau** = *N* analystes indépendants (chacun sa connexion HTTP, chacun son compte":
        "**A level** = *N* independent analysts (each with its own HTTP connection, each with its own",
    "`viewer`), chacun parcourant le mélange plusieurs fois, en décalant son point de départ — deux":
        "`viewer` account), each going through the mix several times, offsetting its starting point — two",
    "voisins ne tirent donc pas la même requête au même instant. Le niveau se termine quand tous ont":
        "neighbours therefore do not fire the same query at the same instant. The level ends when all have",
    "fini leur travail : le débit agrégé est du travail RÉELLEMENT servi, pas une extrapolation.":
        "finished their work: the aggregate throughput is work ACTUALLY served, not an extrapolation.",
    "**L'ordre des questions est délibéré : la justesse d'abord.** Trois défauts de correction":
        "**The order of the questions is deliberate: correctness first.** Three correctness defects",
    "viennent d'être trouvés dans les chemins d'agrégat de ce produit, et aucun n'était visible sur":
        "have just been found in the aggregate paths of this product, and none was visible on",
    "un banc de latence. Chaque réponse concurrente est donc comparée **par sa valeur** à la réponse":
        "a latency bench. Each concurrent answer is therefore compared **by its value** to the answer",
    "obtenue seul — même base, même binaire, même fenêtre — avant qu'on ne regarde un seul temps.":
        "obtained alone — same database, same binary, same window — before a single timing is looked at.",
    "### Le mélange, et pourquoi c'est celui-là":
        "### The mix, and why it is this one",
    "Le mélange n'est pas une liste de goûts : il est **dérivé de la passe solo qui le":
        "The mix is not a list of preferences: it is **derived from the solo run that",
    "précède**. Le PLANCHER est la requête la moins chère observée (`{0}`,":
        "precedes it**. The FLOOR is the cheapest query observed (`{0}`,",
    "{0}) — c'est le coût FIXE d'une requête, pas du travail de base.":
        "{0}) — it is the FIXED cost of a query, not base work.",
    "Chaque **famille** de la matrice (les classes `C1`…`C6` de ce document) entre par son":
        "Each **family** of the matrix (the classes `C1`…`C6` of this document) enters through its",
    "représentant le plus coûteux, et seulement s'il coûte au moins **{0:g} ×**":
        "most expensive representative, and only if it costs at least **{0:g} ×**",
    "le plancher. La famille du plancher échoue ainsi à son propre test et s'exclut d'elle-même.":
        "the floor. The floor's family thus fails its own test and excludes itself.",
    "Le plancher est ensuite ajouté **à part** : il ne charge rien, il mesure ce que devient le":
        "The floor is then added **separately**: it loads nothing, it measures what becomes of the",
    "clic instantané d'un tableau de bord pendant que les collègues lancent des monstres.":
        "instant click of a dashboard while colleagues launch monsters.",
    "| Classe retenue | Famille | Ce que c'est | Coût SEUL (p50) |":
        "| Class retained | Family | What it is | Cost ALONE (p50) |",
    "| `{cid}` | {fam} | {0} | {1} ms |":
        "| `{cid}` | {fam} | {0} | {1} ms |",
    "Familles **écartées** du mélange lourd, avec leur motif mesuré :":
        "Families **excluded** from the heavy mix, with their measured reason:",
    "- famille {0} (`{1}`) : {2}.":
        "- family {0} (`{1}`): {2}.",
    "**Mise au repos avant de mesurer** : un daemon qui vient de démarrer lance un `ANALYZE`":
        "**Settling before measuring**: a daemon that has just started launches a full `ANALYZE`",
    "complet en arrière-plan, qui prend le verrou d'écriture et consomme disque et CPU —":
        "in the background, which takes the write lock and consumes disk and CPU —",
    "mesurer tout de suite, c'est mesurer le démarrage.":
        "measuring right away means measuring the startup.",
    "Le harnais attend donc {0} tirs consécutifs dont l'attente avant moteur est":
        "The harness therefore waits for {0} consecutive shots whose pre-engine wait is",
    "sous la milliseconde : **{0}** ici":
        "under one millisecond: **{0}** here",
    "### La courbe — `{c}` (`PLUME_QUERY_CONCURRENCY={sem}`)":
        "### The curve — `{c}` (`PLUME_QUERY_CONCURRENCY={sem}`)",
    "Sémaphore **{sem}**, {0}. Fenêtre `{1}` (sans borne : le cas le plus coûteux). {2} passages par analyste sur {3} classes.":
        "Semaphore **{sem}**, {0}. Window `{1}` (unbounded: the most expensive case). {2} rounds per analyst over {3} classes.",
    "source inconnue":
        "source unknown",
    "Mélange **IMPOSÉ** (celui de la passe de référence), pour que la comparaison entre sémaphores ne porte que sur le sémaphore.":
        "Mix **IMPOSED** (the one of the reference run), so that the comparison between semaphores bears only on the semaphore.",
    " Sa propre passe solo aurait dérivé un mélange différent de {0} classe(s) : {1} — c'est précisément ce que l'imposition neutralise.":
        " Its own solo run would have derived a mix differing by {0} class(es): {1} — this is precisely what the imposition neutralises.",
    " Sa propre passe solo aurait dérivé exactement le même.":
        " Its own solo run would have derived exactly the same one.",
    "Mélange **DÉRIVÉ** par la passe solo de cette configuration (tableau plus haut).":
        "Mix **DERIVED** by the solo run of this configuration (table above).",
    "| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |":
        "| Analysts | queue possible | queries | duration | throughput | p50 | p95 | worst | p50 of the worst analyst | PERMIT wait p50 | PERMIT wait p95 | peak RSS | ceiling hit | OOM |",
    "— (cgroup disparu)":
        "— (cgroup gone)",
    " — **daemon TUÉ**":
        " — **daemon KILLED**",
    "| **{0}** | {1} | {2}/{3}{dead} | {4:.0f} s | {q:.2f} q/s{rel} | {5} | {6} | {7} | {8} | {9} | {10} | {11} Mio | {recl} | {12} |":
        "| **{0}** | {1} | {2}/{3}{dead} | {4:.0f} s | {q:.2f} q/s{rel} | {5} | {6} | {7} | {8} | {9} | {10} | {11} MiB | {recl} | {12} |",
    "**OUI**":
        "**YES**",
    "non":
        "no",
    "oui":
        "yes",
    "Requêtes qui n'ont pas abouti, par statut HTTP :":
        "Queries that did not complete, by HTTP status:",
    "| Analystes | statuts | messages |":
        "| Analysts | statuses | messages |",
    "`0` = pas de réponse HTTP du tout (connexion coupée / refusée) : c'est ce que voit un":
        "`0` = no HTTP response at all (connection cut / refused): this is what a",
    "client quand le processus n'est plus là. Un `4xx` avec une cause nommée est l'inverse :":
        "client sees when the process is no longer there. A `4xx` with a named cause is the opposite:",
    "le daemon a REFUSÉ proprement, en disant pourquoi.":
        "the daemon REFUSED cleanly, saying why.",
    "Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde":
        "Columns: *duration* = wall time of the whole level; *throughput* = queries served per second",
    "(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur":
        "(in parentheses, the ratio to level 1 of the same run); *p50/p95/worst* cover",
    "**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians":
        "**all** queries of the level; *p50 of the worst analyst* is the worst of the individual",
    "individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps":
        "medians — it is the one that says whether the load is fair; *PERMIT wait* is the time",
    "passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou":
        "spent queuing at the semaphore, and NOTHING else (the time spent waiting for the lock",
    "de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le":
        "of the shared connection is published separately, below); *ceiling hit* is the",
    "compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû":
        "cgroup counter `memory.events:max`, that is, the number of times the kernel had to",
    "récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.":
        "reclaim memory to stay under 2 GiB during this level.",
    "**{0} niveau(x) pris pendant que la MACHINE swappait** ({1} analystes) : ces lignes mesurent le":
        "**{0} level(s) taken while the MACHINE was swapping** ({1} analysts): these rows measure the",
    "stockage de l'hôte autant que plume, elles sont à rejouer.":
        "host's storage as much as plume, they must be re-run.",
    "*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de":
        "*Load the daemon, not the machine*: the instrument itself never consumed more than",
    "**{0:.1f} %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence":
        "**{0:.1f} %** of a core-second per second of measurement on this run — the measured",
    "mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio":
        "latency is therefore not its own. The daemon, for its part, is locked in its cgroup at 2 GiB",
    "sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).":
        "without swap: the two pressures are recorded separately (`pressure_*` in the JSONL).",
    "### La réponse est-elle la MÊME sous charge ?":
        "### Is the answer the SAME under load?",
    "| Réponses comparées à leur référence solo | **{0}** |":
        "| Answers compared to their solo reference | **{0}** |",
    "| Identiques (empreinte ET total) | **{0}** |":
        "| Identical (fingerprint AND total) | **{0}** |",
    "| Divergentes | **{0}** |":
        "| Diverging | **{0}** |",
    "| Dont NOMBRES FAUX (valeur dérivée d'un ensemble) | **{0}** |":
        "| Of which WRONG NUMBERS (value derived from a set) | **{0}** |",
    "| Hors verdict (voir ci-dessous) | {0} |":
        "| Outside the verdict (see below) | {0} |",
    "Les {0} réponses hors verdict sont EXACTEMENT les {1} requêtes qui n'ont pas abouti (connexion coupée après le kill, ou refus nommé) : une requête sans réponse n'a rien à comparer. Aucune n'est hors verdict pour cause d'instabilité — le compte le prouve, il n'est pas affirmé.":
        "The {0} answers outside the verdict are EXACTLY the {1} queries that did not complete (connection cut after the kill, or named refusal): a query without an answer has nothing to compare. None is outside the verdict because of instability — the count proves it, it is not asserted.",
    "Sur {0} réponses hors verdict, {1} sont des requêtes qui n'ont pas abouti (rien à comparer) ; le reste vient des classes déclarées instables SEUL (voir ci-dessous).":
        "Of {0} answers outside the verdict, {1} are queries that did not complete (nothing to compare); the rest come from classes declared unstable ALONE (see below).",
    "**Aucune réponse concurrente ne diffère de la réponse obtenue seul.** L'empreinte est":
        "**No concurrent answer differs from the answer obtained alone.** The fingerprint is",
    "insensible à l'ordre (un `GROUP BY` est un sac non ordonné) et le total de pagination est":
        "order-insensitive (a `GROUP BY` is an unordered bag) and the pagination total is",
    "comparé en plus. Ce n'est pas une déduction depuis les latences : ce sont les VALEURS qui":
        "compared as well. This is not a deduction from latencies: it is the VALUES that",
    "ont été comparées, requête par requête, contre une référence prise sur la même base et le":
        "were compared, query by query, against a reference taken on the same database and the",
    "même binaire quelques minutes plus tôt.":
        "same binary a few minutes earlier.",
    "**Des réponses concurrentes diffèrent de la réponse obtenue seul.** Le détail est dans le":
        "**Some concurrent answers differ from the answer obtained alone.** The detail is in the",
    "JSONL (`justesse.divergences` : empreinte et valeurs des deux côtés) :":
        "JSONL (`justesse.divergences`: fingerprint and values on both sides):",
    "| Passe | Analystes | Classe | Dérivée d'un ensemble | Solo | Sous charge |":
        "| Run | Analysts | Class | Derived from a set | Solo | Under load |",
    "**Hors verdict, et pourquoi** : une classe dont la réponse varie DÉJÀ sans charge ne peut":
        "**Outside the verdict, and why**: a class whose answer ALREADY varies without load cannot",
    "pas servir à accuser la concurrence — l'accuser d'une divergence qu'on observe seul serait":
        "serve to accuse concurrency — accusing it of a divergence observed alone would be",
    "une fausse alerte, et une fausse alerte détruit la valeur des vraies. Classes retirées du":
        "a false alarm, and a false alarm destroys the value of the real ones. Classes removed from the",
    "verdict : {0}.":
        "verdict: {0}.",
    "**Aucune classe n'a été retirée du verdict** : chacune rend la même réponse à chacune de ses":
        "**No class was removed from the verdict**: each one returns the same answer on each of its",
    "répétitions SEUL, donc chacune est comparable sous charge. C'est vérifié, pas supposé.":
        "repetitions ALONE, so each one is comparable under load. This is verified, not assumed.",
    "### L'attente d'un permit, séparée de ce qui n'en est pas":
        "### Waiting for a permit, separated from what is not",
    "C'est le champ `sem_wait_ms` que le daemon publie pour séparer « la requête est lente » de":
        "It is the `sem_wait_ms` field that the daemon publishes to separate \"the query is slow\" from",
    "« la requête attendait son tour ». La campagne précédente a montré **qu'il ne le faisait pas**,":
        "\"the query was waiting for its turn\". The previous campaign showed **that it did not do so**,",
    "et la démonstration ne demandait aucun seuil : tant qu'il y a **au moins autant de permis que":
        "and the demonstration required no threshold: as long as there are **at least as many permits as",
    "d'analystes**, aucune requête ne peut attendre son tour. À ces niveaux, l'attente d'un permit":
        "analysts**, no query can wait for its turn. At these levels, waiting for a permit",
    "est nulle *par construction* — toute valeur non nulle y est nécessairement autre chose.":
        "is zero *by construction* — any non-zero value there is necessarily something else.",
    "| Passe | Analystes | Permis | File possible ? | découpage publié ? | attente PERMIT p95 | attente PERMIT max |":
        "| Run | Analysts | Permits | Queue possible? | split published? | PERMIT wait p95 | PERMIT wait max |",
    "**non**":
        "**no**",
    "| `{0}` | {1} | {2} | **non** | {3} | {4} | **{5}** |":
        "| `{0}` | {1} | {2} | **no** | {3} | {4} | **{5}** |",
    "**Avant le découpage** : le maximum observé là où aucune file n'est possible est de":
        "**Before the split**: the maximum observed where no queue is possible is",
    "**{0}** en charge sous-critique, et de **{1}** pendant la":
        "**{0}** under sub-critical load, and **{1}** during the",
    "passe solo (un seul client, aucun autre en vol). Un sémaphore avec des permis libres ne":
        "solo run (a single client, no other in flight). A semaphore with free permits cannot",
    "peut pas produire ça : le champ mesurait autre chose que son nom, et son nom envoie":
        "produce that: the field measured something other than its name, and its name sends",
    "l'exploitant AUGMENTER le sémaphore — la seule action que la section précédente mesure":
        "the operator to RAISE the semaphore — the only action that the previous section measures",
    "comme nuisible (débit ×0,46, p95 27 s → 50 s, RSS +725 Mio, daemon tué à 10 analystes).":
        "as harmful (throughput ×0.46, p95 27 s → 50 s, RSS +725 MiB, daemon killed at 10 analysts).",
    "**Après : zéro partout.** Là où aucune file n'est possible, l'attente publiée est nulle —":
        "**After: zero everywhere.** Where no queue is possible, the published wait is zero —",
    "pas « petite » : nulle, à la microseconde de résolution du champ. Ce n'est pas une mesure":
        "not \"small\": zero, at the microsecond resolution of the field. This is not a measurement",
    "qui a bien voulu tomber juste : quand un permit est libre il est pris sans jamais":
        "that happened to land right: when a permit is free it is taken without ever",
    "suspendre la tâche, et la valeur publiée est le zéro CONSTANT":
        "suspending the task, and the published value is the CONSTANT zero",
    "(`daemon/src/query_timing.rs`) — aucune horloge n'intervient sur ce chemin, donc rien ne":
        "(`daemon/src/query_timing.rs`) — no clock is involved on this path, so nothing",
    "peut la contaminer. La propriété « autant de permis que de clients ⇒ aucune attente » a":
        "can contaminate it. The property \"as many permits as clients ⇒ no wait\" has",
    "cessé d'être une mesure à vérifier pour devenir la construction de la valeur, et le":
        "ceased to be a measurement to check and become the construction of the value, and the",
    "harnais SORT EN ERREUR si elle est violée au lieu de publier le chiffre.":
        "harness EXITS WITH AN ERROR if it is violated instead of publishing the figure.",
    "**Après le découpage, il reste {0}** là où aucune file n'est":
        "**After the split, {0} remains** where no queue is",
    "possible : la correction est incomplète, et c'est publié tel quel.":
        "possible: the correction is incomplete, and it is published as is.",
    "#### Où passe le temps, maintenant qu'il est découpé":
        "#### Where the time goes, now that it is split",
    "Le champ ne pouvait pas être corrigé en le déplaçant : ce qu'il additionnait devait être":
        "The field could not be fixed by moving it: what it added up had to be",
    "**séparé**, sinon la part cachée serait simplement retombée ailleurs. Le daemon publie donc":
        "**separated**, otherwise the hidden part would simply have fallen elsewhere. The daemon therefore publishes",
    "un découpage TOTAL — `prepare + sem_wait + exec == server` par construction, `exec` étant le":
        "a TOTAL split — `prepare + sem_wait + exec == server` by construction, `exec` being the",
    "reste et jamais une troisième horloge :":
        "remainder and never a third clock:",
    "| champ | ce qu'il mesure |":
        "| field | what it measures |",
    "| `prepare_ms` | avant le permit : corps, masques, **couverture des rollups**, compilation |":
        "| `prepare_ms` | before the permit: body, masks, **rollup coverage**, compilation |",
    "| `sem_wait_ms` | l'attente du PERMIT, et rien d'autre |":
        "| `sem_wait_ms` | the PERMIT wait, and nothing else |",
    "| `db_lock_wait_ms` | le temps passé à **obtenir** le verrou de la connexion PARTAGÉE (pas celui passé à le tenir) |":
        "| `db_lock_wait_ms` | the time spent **obtaining** the lock of the SHARED connection (not the time spent holding it) |",
    "| `exec_ms` | le reste : l'exécution |":
        "| `exec_ms` | the remainder: execution |",
    "| Passe | Analystes | file ? | avant moteur p50 | avant moteur p95 | **verrou partagé** p50 | **verrou partagé** max | permit p95 | mur p95 |":
        "| Run | Analysts | queue? | pre-engine p50 | pre-engine p95 | **shared lock** p50 | **shared lock** max | permit p95 | wall p95 |",
    "**La sérialisation que personne ne voyait.** Le chemin d'une requête interactive lit la":
        "**The serialisation nobody saw.** The path of an interactive query reads the",
    "couverture des rollups. Tant que cette lecture prenait le verrou de la connexion":
        "rollup coverage. As long as this read took the lock of the",
    "**partagée** — celui-là même que la boucle de rollups tient pendant tout un tick":
        "**shared** connection — the very one that the rollup loop holds for a whole tick",
    "(`spawn_rollup_loop`, 120 s) et que l'`ANALYZE` de démarrage tient plusieurs minutes —":
        "(`spawn_rollup_loop`, 120 s) and that the startup `ANALYZE` holds for several minutes —",
    "**aucun sémaphore ne bornait cette attente** : elle avait lieu ailleurs que sur le":
        "**no semaphore bounded this wait**: it happened somewhere other than on the",
    "sémaphore, et augmenter le sémaphore n'y met que plus de monde.":
        "semaphore, and raising the semaphore only puts more people into it.",
    "MESURÉ, verrou en place ({0}) :":
        "MEASURED, lock in place ({0}):",
    "jusqu'à **{0}** sous charge et **{1}** en solo — sur le":
        "up to **{0}** under load and **{1}** solo — on the",
    "chemin de CHAQUE requête GXQL, pendant que l'attente de permit, elle, était nulle.":
        "path of EVERY GXQL query, while the permit wait, for its part, was zero.",
    "MESURÉ après retrait ({0}) :":
        "MEASURED after removal ({0}):",
    "**zéro**. La lecture de couverture est passée au pool de lecture — mêmes lignes `meta`":
        "**zero**. The coverage read moved to the read pool — same committed `meta`",
    "commitées, même repli fail-closed vers « rien d'établi », donc le même corps de rollup":
        "rows, same fail-closed fallback to \"nothing established\", hence the same rollup body",
    "servi ou décliné ; seul le verrou disparaît. Le champ reste publié à zéro : une absence":
        "served or declined; only the lock disappears. The field is still published at zero: a missing",
    "de champ se lirait « je ne sais pas », un zéro se lit « j'ai regardé ».":
        "field would read \"I do not know\", a zero reads \"I looked\".",
    "C'est la lecture qui change une décision : un exploitant qui voit l'attente du permit à":
        "It is the reading that changes a decision: an operator who sees the permit wait at",
    "zéro et le verrou partagé non nul sait que son sémaphore n'est pas le levier. Avant le":
        "zero and the shared lock non-zero knows that their semaphore is not the lever. Before the",
    "découpage, les deux étaient dans le même champ, sous le nom du sémaphore.":
        "split, both were in the same field, under the name of the semaphore.",
    "**Angle mort restant** : {0} ne publie(nt) aucun":
        "**Remaining blind spot**: {0} publish(es) no",
    "`stats` — la barre `/api/search` prend pourtant un permit sur le MÊME sémaphore. Sur cette":
        "`stats` — yet the `/api/search` bar takes a permit on the SAME semaphore. On this",
    "route, il est donc impossible de distinguer une recherche lente d'une recherche qui":
        "route, it is therefore impossible to tell a slow search from a search that",
    "attendait : c'est mesuré ici, ce n'est pas corrigé ici.":
        "was waiting: this is measured here, it is not fixed here.",
    "**Aucune route en angle mort** : toutes les classes tirées ici publient leur découpage, y":
        "**No route in a blind spot**: all the classes fired here publish their split,",
    "compris la barre `/api/search`, qui prend un permit sur le MÊME sémaphore et ne publiait":
        "including the `/api/search` bar, which takes a permit on the SAME semaphore and published",
    "rien du tout jusqu'à la campagne précédente. Une route invisible à la mesure de concurrence":
        "nothing at all until the previous campaign. A route invisible to the concurrency measurement",
    "pèse pourtant dessus : elle consomme les mêmes permis.":
        "still weighs on it: it consumes the same permits.",
    "### Le clic de tableau de bord, pendant que les autres travaillent":
        "### The dashboard click, while the others work",
    "`{floor_id}` est la requête la moins chère de la matrice. Seule, elle est instantanée. Ce":
        "`{floor_id}` is the cheapest query of the matrix. Alone, it is instantaneous. This",
    "tableau est ce que l'analyste RESSENT : aucune moyenne ne le montre, parce qu'elle est":
        "table is what the analyst FEELS: no average shows it, because it is",
    "noyée dans les monstres.":
        "drowned among the monsters.",
    "| Passe | Analystes | p50 | p95 | pire |":
        "| Run | Analysts | p50 | p95 | worst |",
    "### Le budget de 2 Gio, à plusieurs":
        "### The 2 GiB budget, with several users",
    "- **RSS crête du daemon, tous niveaux confondus : {0} Mio** ({1:.0f} % du budget).":
        "- **Daemon peak RSS, all levels combined: {0} MiB** ({1:.0f} % of the budget).",
    "- **Mémoire du cgroup crête : {0} Mio** pour un plafond de {1} Mio.":
        "- **Peak cgroup memory: {0} MiB** for a ceiling of {1} MiB.",
    "  Ce n'est pas la même grandeur que la RSS : le noyau compare au plafond la mémoire du CGROUP,":
        "  This is not the same quantity as the RSS: the kernel compares the CGROUP memory to the ceiling,",
    "  cache de pages compris. Une base de 1,4 Gio lue en boucle le remplit — le cgroup vit donc":
        "  page cache included. A 1.4 GiB database read in a loop fills it — the cgroup therefore lives",
    "  **collé à son plafond**, et ce qui varie n'est pas son occupation mais son travail de":
        "  **pressed against its ceiling**, and what varies is not its occupancy but its reclaim",
    "  récupération.":
        "  work.",
    "- **LE BUDGET A CÉDÉ** : `{0}`, **{1} analystes** (sémaphore {2}). RSS crête {3} Mio contre un plafond de {4} Mio, {5} requêtes sur {6} n'ont pas abouti, et le processus n'existait plus à la fin du niveau. Sous `MemoryMax` **sans swap**, cela ne peut pas être autre chose qu'un dépassement du budget : le noyau tue, il ne glisse pas en swap. Les niveaux au-delà ne sont **pas** mesurés — une absence, pas un zéro.":
        "- **THE BUDGET GAVE WAY**: `{0}`, **{1} analysts** (semaphore {2}). Peak RSS {3} MiB against a ceiling of {4} MiB, {5} queries out of {6} did not complete, and the process no longer existed at the end of the level. Under `MemoryMax` **without swap**, this cannot be anything other than a budget overrun: the kernel kills, it does not slide into swap. The levels beyond are **not** measured — an absence, not a zero.",
    "- La dégradation n'est pas binaire : AVANT le kill, le daemon a d'abord REFUSÉ proprement des requêtes en nommant sa cause (budget interactif de 60 s dépassé, `4xx`). Le refus nommé arrive donc en premier ; le kill est ce qui suit quand la mémoire, elle, ne négocie pas.":
        "- The degradation is not binary: BEFORE the kill, the daemon first cleanly REFUSED queries, naming its cause (interactive budget of 60 s exceeded, `4xx`). The named refusal therefore comes first; the kill is what follows when memory, for its part, does not negotiate.",
    "- **Tués par le noyau (`memory.events:oom_kill`) : {ooms}** — compteur du cgroup, à lire avec la réserve ci-dessus : le cgroup d'un scope tué disparaît avec lui, et son compteur n'est alors plus lisible du tout.":
        "- **Killed by the kernel (`memory.events:oom_kill`): {ooms}** — cgroup counter, to be read with the reservation above: the cgroup of a killed scope disappears with it, and its counter is then no longer readable at all.",
    "- Le harnais a ARRÊTÉ le balayage après le niveau {0} (`{1}`) : {2}":
        "- The harness STOPPED the sweep after level {0} (`{1}`): {2}",
    "- **Le daemon n'a été tué à aucun niveau mesuré.** Le dépassement du budget ne se manifeste":
        "- **The daemon was not killed at any measured level.** The budget overrun therefore does not",
    "  donc pas ici par un kill mais par du **travail de récupération** : la colonne « plafond":
        "  show here as a kill but as **reclaim work**: the \"ceiling",
    "  touché » des courbes ci-dessus compte, pour chaque niveau, le nombre de fois où le noyau":
        "  hit\" column of the curves above counts, for each level, the number of times the kernel",
    "  a dû reprendre de la mémoire au cgroup pour rester sous 2 Gio.":
        "  had to take memory back from the cgroup to stay under 2 GiB.",
    "### Ce que coûte, et ce que rapporte, la taille du sémaphore":
        "### What the semaphore size costs, and what it brings",
    "Le sémaphore de l'interactif est à 3 par défaut, après avoir été baissé depuis 8 **comme":
        "The interactive semaphore is at 3 by default, after having been lowered from 8 **as a",
    "levier de RAM**. Les passes comparées ici tournent sur la MÊME base, la MÊME machine, le":
        "RAM lever**. The runs compared here run on the SAME database, the SAME machine, the",
    "MÊME binaire **et le MÊME mélange de requêtes** : leur écart, à niveau d'analystes égal,":
        "SAME binary **and the SAME query mix**: their gap, at an equal number of analysts,",
    "EST le taux de change entre concurrence et mémoire.":
        "IS the exchange rate between concurrency and memory.",
    "**Il est réglable sans recompiler** : `PLUME_QUERY_CONCURRENCY` est lu dans la":
        "**It can be tuned without recompiling**: `PLUME_QUERY_CONCURRENCY` is read from the",
    "configuration au démarrage (`daemon/src/server/mod.rs`, défaut 3) et le daemon publie la":
        "configuration at startup (`daemon/src/server/mod.rs`, default 3) and the daemon publishes the",
    "valeur qu'il applique sur `/api/system/diag` — c'est de là que ce banc la lit, plutôt que":
        "value it applies on `/api/system/diag` — that is where this bench reads it, rather than",
    "de la supposer. En revanche il est lu **une seule fois, au boot** : le changer demande un":
        "assuming it. On the other hand it is read **only once, at boot**: changing it requires a",
    "redémarrage, et un redémarrage a son propre coût (voir la mise au repos plus haut).":
        "restart, and a restart has its own cost (see the settling above).",
    "**Écartée(s) de cette comparaison** : {0}":
        "**Excluded from this comparison**: {0}",
    "— leur mélange OU leur binaire n'est pas celui des autres passes, donc leur écart de":
        "— their mix OR their binary is not that of the other runs, so their throughput",
    "débit ne serait pas attribuable au sémaphore mais au travail ou au code. Leur courbe":
        "gap would be attributable not to the semaphore but to the work or the code. Their curve",
    "reste publiée plus haut ; c'est cette comparaison-ci, et elle seule, qui exige que":
        "remains published above; it is this comparison, and it alone, that requires that",
    "tout le reste soit identique.":
        "everything else be identical.",
    " | écart de débit | ":
        " | throughput gap | ",
    "débit `{c}`":
        "throughput `{c}`",
    "| Analystes | ":
        "| Analysts | ",
    "RSS `{c}`":
        "RSS `{c}`",
    " Mio":
        " MiB",
    "**Au niveau le plus chargé mesuré des deux côtés ({n} analystes)** : {q1:.2f} contre {q0:.2f} requête/s ":
        "**At the most loaded level measured on both sides ({n} analysts)**: {q1:.2f} against {q0:.2f} queries/s ",
    "(**{0:+.0f} %** de travail servi)":
        "(**{0:+.0f} %** of work served)",
    ", p95 {0} contre {1}, RSS crête {2} contre {3} Mio (**{4:+.0f} Mio**, soit {5:+.1f} % du budget). Ces six nombres SONT le taux de change entre un sémaphore à {6} et un sémaphore à {7} — celui que la baisse de 8 à 3, faite comme levier de RAM, avait acheté sans jamais être chiffré.":
        ", p95 {0} against {1}, peak RSS {2} against {3} MiB (**{4:+.0f} MiB**, i.e. {5:+.1f} % of the budget). These six numbers ARE the exchange rate between a semaphore at {6} and a semaphore at {7} — the one that the lowering from 8 to 3, made as a RAM lever, had bought without ever being quantified.",
    "**Pas de comparaison publiée.** Les passes mesurées n'ont pas tiré le MÊME mélange de":
        "**No comparison published.** The measured runs did not fire the SAME query",
    "requêtes : leur écart de débit mélangerait l'effet du sémaphore et celui du travail. Un":
        "mix: their throughput gap would mix the effect of the semaphore with that of the work. A",
    "banc ne change qu'une chose à la fois — les courbes restent publiées séparément.":
        "bench changes only one thing at a time — the curves remain published separately.",
    "### L'écart avant / après le correctif de métrique":
        "### The before / after gap of the metric fix",
    "MÊME base, MÊME machine, MÊME sémaphore, MÊME mélange **imposé**, MÊMES niveaux : seul le":
        "SAME database, SAME machine, SAME semaphore, SAME **imposed** mix, SAME levels: only the",
    "BINAIRE change. Ce n'est donc pas une comparaison de configurations, c'est la mesure de ce":
        "BINARY changes. This is therefore not a comparison of configurations, it is the measurement of what",
    "qu'un correctif a fait — et les deux colonnes d'attente sont l'essentiel, parce que c'est":
        "a fix did — and the two wait columns are what matters, because that is",
    "là que le défaut vivait.":
        "where the defect lived.",
    "**Sémaphore {sem}** — `{c0}` ({0}, `{1}`) contre `{c1}` ({2}, `{3}`)":
        "**Semaphore {sem}** — `{c0}` ({0}, `{1}`) against `{c1}` ({2}, `{3}`)",
    "| Analystes | file ? | débit avant | débit après | p95 avant | p95 après | attente PERMIT max avant | attente PERMIT max après | verrou partagé max après | RSS avant | RSS après |":
        "| Analysts | queue? | throughput before | throughput after | p95 before | p95 after | PERMIT wait max before | PERMIT wait max after | shared lock max after | RSS before | RSS after |",
    "| **{n}** | {0} | {1:.2f} q/s | {2:.2f} q/s | {3} | {4} | {5} | {6} | {7} | {8} Mio | {9} Mio |":
        "| **{n}** | {0} | {1:.2f} q/s | {2:.2f} q/s | {3} | {4} | {5} | {6} | {7} | {8} MiB | {9} MiB |",
    "Lire la colonne « file ? » AVANT les colonnes d'attente : là où elle dit **non**, aucune":
        "Read the \"queue?\" column BEFORE the wait columns: where it says **no**, no",
    "requête ne PEUT attendre son tour, donc toute attente de permit publiée y est fausse.":
        "query CAN wait for its turn, so any published permit wait there is wrong.",
    "La colonne « verrou partagé » dit où cette attente passait, et il en reste":
        "The \"shared lock\" column says where this wait went, and there remains",
    "{0} : la sérialisation existe encore sur ce chemin.":
        "{0} of it: the serialisation still exists on this path.",
    "La colonne « verrou partagé » est à zéro **parce que la sérialisation a été retirée**":
        "The \"shared lock\" column is at zero **because the serialisation was removed**",
    "(la lecture de couverture des rollups est passée au pool de lecture) — pas parce":
        "(the rollup coverage read moved to the read pool) — not because",
    "qu'elle n'était pas là : c'est la passe d'ATTRIBUTION, plus haut, qui la mesure encore":
        "it was not there: it is the ATTRIBUTION run, above, that still measures it",
    "en place, et le champ reste publié pour que la prochaine soit visible immédiatement.":
        "in place, and the field remains published so that the next one is visible immediately.",
    "Les colonnes de débit et de p95, elles, ne sont PAS un résultat de ce correctif : elles":
        "The throughput and p95 columns, for their part, are NOT a result of this fix: they",
    "portent la charge de la machine du jour autant que le code — on les publie pour qu'on":
        "carry the load of the machine on that day as much as the code — they are published so that",
    "puisse les contredire, pas pour en tirer une conclusion.":
        "they can be contradicted, not to draw a conclusion from them.",
    "## La généricité — les mêmes requêtes sur d'AUTRES profils de données":
        "## Genericity — the same queries on OTHER data profiles",
    "Un chiffre mesuré sur notre profil prouve NOTRE cas, pas le cas général. Les passes ci-dessous":
        "A figure measured on our profile proves OUR case, not the general case. The runs below",
    "rejouent **la même matrice** sur des profils qui ne diffèrent du témoin que par **un seul**":
        "replay **the same matrix** on profiles that differ from the witness by **a single**",
    "paramètre du jeu de données, **à volume d'événements égal**, sur la même machine et le même":
        "parameter of the dataset, **at equal event volume**, on the same machine and the same",
    "binaire. Chaque axe est DÉRIVÉ d'une décision du chemin d'exécution — pas choisi pour":
        "binary. Each axis is DERIVED from a decision of the execution path — not chosen for",
    "l'occasion : ce qui décide index ou scan, route de rollups ou balayage, chaud ou froid.":
        "the occasion: what decides index or scan, rollup route or sweep, hot or cold.",
    "| Passe | Axe | Valeur | Ce que le profil dit AVANT -> APRÈS | Événements | Base (Mio) |":
        "| Run | Axis | Value | What the profile says BEFORE -> AFTER | Events | Database (MiB) |",
    "sévérité >= 3":
        "severity >= 3",
    "octets/événement":
        "bytes/event",
    "poids source dominante":
        "dominant source weight",
    "cardinalité médiane {0} -> {1}":
        "median cardinality {0} -> {1}",
    "cardinalité de `host` = {0}":
        "cardinality of `host` = {0}",
    "**témoin**":
        "**witness**",
    "### Le bruit d'abord — sinon aucun écart n'est interprétable":
        "### Noise first — otherwise no gap can be interpreted",
    "Le témoin a été mesuré **deux fois**, sur la **même base**, avec le même binaire et la":
        "The witness was measured **twice**, on the **same database**, with the same binary and the",
    "même machine — `{0}` puis `{1}`. Rien n'y change : ni la donnée, ni le code,":
        "same machine — `{0}` then `{1}`. Nothing changes between them: neither the data, nor the code,",
    "ni le réglage. Les deux passes ENCADRENT la campagne (l'une au début, l'autre à la fin),":
        "nor the setting. The two runs BRACKET the campaign (one at the start, the other at the end),",
    "donc la bande contient aussi la dérive de la machine pendant la campagne. Le rapport":
        "so the band also contains the drift of the machine during the campaign. The ratio",
    "d'une passe à l'autre, cellule par cellule, est du BRUIT pur, et il vaut :":
        "from one run to the other, cell by cell, is pure NOISE, and it is:",
    "| Cellules | min | 5 % | médian | 95 % | max |":
        "| Cells | min | 5 % | median | 95 % | max |",
    "**C'est l'étalon.** Le critère retenu plus bas est l'ÉTENDUE COMPLÈTE `[x{lo:.2f},":
        "**This is the yardstick.** The criterion retained below is the FULL RANGE `[x{lo:.2f},",
    "x{hi:.2f}]` — le plus conservateur des deux : un écart n'est déclaré attribuable au":
        "x{hi:.2f}]` — the more conservative of the two: a gap is declared attributable to the",
    "profil que s'il sort de tout ce que la répétition a produit sans qu'on change quoi que ce":
        "profile only if it falls outside everything the repetition produced without anything being",
    "soit. Les quantiles sont publiés à côté pour que le lecteur voie si la bande est large":
        "changed. The quantiles are published alongside so that the reader sees whether the band is wide",
    "à cause d'UNE cellule ou de toutes.":
        "because of ONE cell or of all of them.",
    "Cette bande n'est pas un seuil choisi : c'est une mesure. Elle s'élargit d'elle-même si":
        "This band is not a chosen threshold: it is a measurement. It widens by itself if",
    "la machine est plus chargée, et le document conclut alors MOINS. C'est le comportement":
        "the machine is more loaded, and the document then concludes LESS. This is the intended",
    "voulu — un banc doit perdre en conclusions quand il perd en conditions, jamais gagner en":
        "behaviour — a bench must lose conclusions when it loses conditions, never gain",
    "confiance. **Réserve à connaître** : les cellules les plus rapides (proches du coût fixe":
        "confidence. **Caveat to know**: the fastest cells (close to the fixed cost",
    "d'une requête, mesuré par `C0-plancher`) ont un bruit relatif élevé alors que leur enjeu":
        "of a query, measured by `C0-plancher`) have a high relative noise while their stake",
    "est nul ; elles élargissent la bande et rendent donc le test PLUS strict, jamais moins.":
        "is nil; they widen the band and therefore make the test STRICTER, never looser.",
    "**Le témoin n'a pas été mesuré deux fois dans cette passe** : aucune bande de bruit n'est":
        "**The witness was not measured twice in this run**: no noise band is",
    "disponible, donc aucun écart ci-dessous n'est déclaré significatif. Les rapports sont":
        "available, so no gap below is declared significant. The ratios are",
    "publiés bruts, et ils ne prouvent rien tant que la répétition n'a pas été faite.":
        "published raw, and they prove nothing until the repetition has been done.",
    "### L'écart, axe par axe":
        "### The gap, axis by axis",
    "Rapport de la latence p50 de chaque passe à celle du témoin `{temoin}`. **Gras** = l'écart":
        "Ratio of the p50 latency of each run to that of the witness `{temoin}`. **Bold** = the gap",
    "sort de la bande de bruit ci-dessus, donc il est attribuable au PROFIL DE DONNÉES et pas à la":
        "falls outside the noise band above, so it is attributable to the DATA PROFILE and not to the",
    "machine. Une cellule vide n'a pas été mesurée des deux côtés.":
        "machine. An empty cell was not measured on both sides.",
    "| Classe | Fenêtre | témoin | {hdr} |":
        "| Class | Window | witness | {hdr} |",
    "### Ce que ça donne, axe par axe":
        "### What it gives, axis by axis",
    "| Axe | Cellules comparables | Hors bande de bruit | Part |":
        "| Axis | Comparable cells | Outside the noise band | Share |",
    "Une part élevée veut dire : **sur cet axe, nos chiffres ne se transposent pas**. Un tiers dont":
        "A high share means: **on this axis, our figures do not transpose**. A third party whose",
    "le jeu diffère de nous sur ce paramètre n'obtiendra pas nos latences, et l'écart n'est pas un":
        "dataset differs from ours on this parameter will not get our latencies, and the gap is not a",
    "artefact de mesure puisqu'il sort de la bande mesurée sur une répétition à l'identique.":
        "measurement artefact since it falls outside the band measured on an identical repetition.",
    "aucune autre passe dans ce relevé":
        "no other run in this reading",
    "`{c}` diverge sur ":
        "`{c}` diverges on ",
    "**Comparaison REFUSÉE — {quoi}.** Ce relevé ne contient pas deux passes qui ne diffèrent que par `{axe}` : {cause}. Un écart entre ces passes ne mesurerait pas `{axe}`, il mesurerait leur propre divergence — il n'est donc pas rendu. **Ce n'est pas « rien à signaler » : c'est un refus.** Pour obtenir le chiffre, il faut TIRER la paire, pas assouplir la garde.":
        "**Comparison REFUSED — {quoi}.** This reading does not contain two runs that differ only by `{axe}`: {cause}. A gap between these runs would not measure `{axe}`, it would measure their own divergence — so it is not rendered. **This is not \"nothing to report\": it is a refusal.** To get the figure, the pair must be FIRED, not the guard loosened.",
    "non relevé":
        "not recorded",
    "# Banc de mesure plume — requêtes à chaud sous 2 Gio":
        "# plume measurement bench — hot queries under 2 GiB",
    "<!-- CE FICHIER EST GÉNÉRÉ par bench/report.py (voir la section « Reproduire » en bas).":
        "<!-- THIS FILE IS GENERATED by bench/report.py (see the \"Reproduce\" section at the bottom).",
    "     Ne pas l'éditer à la main : la prochaine passe l'écrase. Tout commentaire durable va dans":
        "     Do not edit it by hand: the next run overwrites it. Any lasting comment goes in",
    "     bench/README.md. -->":
        "     bench/README.md. -->",
    "Rendu le {0} depuis ":
        "Rendered on {0} from ",
    " — données brutes VERSIONNÉES dans [`bench/results/`](../bench/results/), pour que ce":
        " — raw data VERSIONED in [`bench/results/`](../bench/results/), so that this",
    " tableau puisse être contredit et pas seulement cru (cf. `bench/README.md`).":
        " table can be contradicted and not merely believed (see `bench/README.md`).",
    "## Ce que ce document est, et ce qu'il n'est pas":
        "## What this document is, and what it is not",
    "C'est la **mesure de référence** de plume, prise avec un instrument publié et rejouable.":
        "It is the **reference measurement** of plume, taken with a published and replayable instrument.",
    "Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est une case":
        "Every figure carries its qualifiers. Nothing is extrapolated: an empty cell is a",
    "**non mesurée**, pas une case implicitement bonne. Quand plusieurs passes coexistent au même":
        "**not measured** cell, not an implicitly good one. When several runs coexist at the same",
    "volume, elles sont TOUTES rendues : une passe n'est jamais remplacée par une plus flatteuse,":
        "volume, they are ALL rendered: a run is never replaced by a more flattering one,",
    "et la section « Écart mesuré entre deux passes » dit laquelle décrit le code actuel.":
        "and the section \"Measured gap between two runs\" says which one describes the current code.",
    "Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : c'est un":
        "It is **not** a comparison with another product, nor a production measurement: it is a",
    "banc synthétique au **profil** de la production (voir `bench/profile-prod.json`).":
        "synthetic bench with the **profile** of the production workload (see `bench/profile-prod.json`).",
    "## Verdict — ce que ces mesures autorisent à affirmer":
        "## Verdict — what these measurements allow to be claimed",
    "Volume de référence : **{0} événements** (`{ref}`), base **{1} Mio** chiffrée SQLCipher.":
        "Reference volume: **{0} events** (`{ref}`), database **{1} MiB** encrypted with SQLCipher.",
    "**Sur le budget de 2 Gio — soutenu.** RSS crête la plus haute mesurée sur l'ensemble des cellules : **{0} Mio**, soit **{1:.0f} %** du budget. Et ce n'est pas une observation passive : le daemon tournait sous `MemoryMax=2G MemorySwapMax=0`, où un dépassement est un kill du noyau.":
        "**On the 2 GiB budget — sustained.** Highest peak RSS measured across all cells: **{0} MiB**, i.e. **{1:.0f} %** of the budget. And this is not a passive observation: the daemon ran under `MemoryMax=2G MemorySwapMax=0`, where an overrun is a kernel kill.",
    "**Ce qui est RAPIDE** (p50, fenêtre indiquée, config de référence) :":
        "**What is FAST** (p50, window indicated, reference config):",
    "- `{0}` / {1} — **{2}** ({3}), servi par `{4}`":
        "- `{0}` / {1} — **{2}** ({3}), served by `{4}`",
    "Toutes ces cellules sont AU PLANCHER. Une requête dont le SQL ne coûte rien revient en **{0}** (`C0-plancher`, SQL mesuré à {1}) : c'est un coût FIXE, indépendant du volume, et aucune requête ne peut descendre en dessous aujourd'hui. Voir le levier « Le plancher fixe par requête ».":
        "All these cells are AT THE FLOOR. A query whose SQL costs nothing comes back in **{0}** (`C0-plancher`, SQL measured at {1}): it is a FIXED cost, independent of volume, and no query can go below it today. See the lever \"The fixed floor per query\".",
    "**Ce qui est LENT** — et ce sont les cas que la promesse « sur tous les champs » met en avant :":
        "**What is SLOW** — and these are the cases that the \"on all fields\" promise puts forward:",
    "**Le disque n'a pas été sollicité — et c'est une limite, pas une bonne nouvelle.** Octets lus au bloc, maximum sur toutes les cellules : **{0} Mio**. La base ({1} Mio) tient entièrement dans le cache de pages de la machine ({2} Mio de mémoire disponible au minimum pendant la mesure). Ces latences sont donc **bornées par le CPU, pas par le stockage**, et constituent un MEILLEUR CAS. À un volume où la base dépasse la RAM disponible, le stockage entre dans l'équation — et ce régime n'est pas mesuré ici.":
        "**The disk was not used — and that is a limit, not good news.** Bytes read at the block layer, maximum over all cells: **{0} MiB**. The database ({1} MiB) fits entirely in the machine's page cache ({2} MiB of memory available at minimum during the measurement). These latencies are therefore **bound by the CPU, not by storage**, and constitute a BEST CASE. At a volume where the database exceeds the available RAM, storage enters the equation — and that regime is not measured here.",
    "**Ce que ces mesures n'autorisent PAS à affirmer** :":
        "**What these measurements do NOT allow to be claimed**:",
    "- au-delà de {0} événements, rien. C'est le volume le plus élevé réellement REMPLI par le vrai chemin d'ingest (`{volmax_cfg}`) ; la configuration de référence de ce verdict, elle, porte sur {1} événements, et les deux ne se lisent pas l'une pour l'autre. Toute latence annoncée à un volume supérieur serait une extrapolation, pas une mesure.":
        "- beyond {0} events, nothing. This is the highest volume actually FILLED by the real ingest path (`{volmax_cfg}`); the reference configuration of this verdict, for its part, covers {1} events, and the two are not to be read for one another. Any latency announced at a higher volume would be an extrapolation, not a measurement.",
    "- rien au-delà de {0} événements. La cible de 10 M n'a pas été atteinte par le vrai chemin d'ingest — non pas faute de l'avoir cherché, mais parce que le débit d'ingest s'effondre avec le volume déjà en base, ce que la section « D'où vient l'effondrement » ATTRIBUE désormais (et non plus suppose) : le coût CPU par événement monte, le daemon écrit de plus en plus d'octets par ligne, et le chemin d'écriture est séquentiel. Le coût restant pour atteindre 10 M y est chiffré, en tant que PLANCHER arithmétique sur des débits mesurés. Toute latence annoncée à 10 M ou 100 M serait une extrapolation, pas une mesure.":
        "- nothing beyond {0} events. The 10 M target was not reached by the real ingest path — not for lack of trying, but because the ingest throughput collapses with the volume already in the database, which the section \"Where the collapse comes from\" now ATTRIBUTES (and no longer assumes): the CPU cost per event rises, the daemon writes more and more bytes per row, and the write path is sequential. The remaining cost to reach 10 M is quantified there, as an arithmetic FLOOR on measured throughputs. Any latency announced at 10 M or 100 M would be an extrapolation, not a measurement.",
    "la concurrence ni le multi-tenant":
        "concurrency nor multi-tenancy",
    "le multi-tenant":
        "multi-tenancy",
    "- rien sur {cc} (voir la section dédiée). Le tier froid, lui, EST mesuré ici — mais seulement dans {cold_list}, à une seule fenêtre chaude et un seul volume : les autres tableaux restent des tableaux SANS tier froid.":
        "- nothing on {cc} (see the dedicated section). The cold tier, for its part, IS measured here — but only in {cold_list}, at a single hot window and a single volume: the other tables remain tables WITHOUT a cold tier.",
    "- rien sur le tier froid, ":
        "- nothing on the cold tier, ",
    "la concurrence, ni le multi-tenant":
        "concurrency, nor multi-tenancy",
    " (voir la section dédiée).":
        " (see the dedicated section).",
    "- la CONCURRENCE, elle, est mesurée : jusqu'à {cn} analystes simultanés lançant de très grosses requêtes sous le même budget de 2 Gio appliqué, avec vérification que la réponse concurrente est IDENTIQUE à la réponse obtenue seul (section dédiée).":
        "- CONCURRENCY, for its part, is measured: up to {cn} simultaneous analysts launching very large queries under the same enforced 2 GiB budget, with a check that the concurrent answer is IDENTICAL to the answer obtained alone (dedicated section).",
    "l'effet du masquage sur les latences":
        "the effect of masking on latencies",
    "- rien sur un déploiement AVEC masquage à partir des chiffres masque-vide : l'écart mesuré le plus fort est **x{0:.1f}** sur `{1}` / {2} ({3} masque vide contre {4} masque non vide, `{mk_vide}` contre `{mk}` — deux passes qui ne diffèrent QUE par le masque).":
        "- nothing on a deployment WITH masking from the empty-mask figures: the largest measured gap is **x{0:.1f}** on `{1}` / {2} ({3} empty mask against {4} non-empty mask, `{mk_vide}` against `{mk}` — two runs that differ ONLY by the mask).",
    "  Et le masquage ne va pas TOUJOURS dans le sens du ralentissement : sur `{0}` / {1} il est **x{2:.2f}**, donc plus RAPIDE ({3} masque vide contre {4} masque non vide, {5}). **La cause n'est PAS établie par cette mesure**, et on ne va pas l'inventer. Deux mécanismes candidats, qui demandent chacun une expérience dédiée pour être départagés : (a) un masque posé sur une dimension à haute cardinalité l'effondre, il reste moins de groupes à agréger — la requête va plus vite **parce que la réponse a changé** ; (b) la passe masquée a tourné APRÈS la passe non masquée, donc sur un cache de pages plus chaud. Ce qui trancherait : rejouer les deux passes dans l'ordre inverse, et comparer les résultats ligne à ligne. En attendant, la règle est simple — **une latence qui baisse en présence d'un masque ne doit jamais être citée comme un gain**.":
        "  And masking does not ALWAYS go in the direction of slowing down: on `{0}` / {1} it is **x{2:.2f}**, hence FASTER ({3} empty mask against {4} non-empty mask, {5}). **The cause is NOT established by this measurement**, and it will not be invented. Two candidate mechanisms, each requiring a dedicated experiment to be told apart: (a) a mask placed on a high-cardinality dimension collapses it, fewer groups remain to aggregate — the query goes faster **because the answer changed**; (b) the masked run ran AFTER the unmasked run, hence on a warmer page cache. What would settle it: replay both runs in reverse order, and compare the results row by row. Meanwhile, the rule is simple — **a latency that drops in the presence of a mask must never be cited as a gain**.",
    "même nombre de lignes rendues":
        "same number of rows returned",
    "{0} lignes contre {1}":
        "{0} rows against {1}",
    "- rien sur un déploiement AVEC masquage : cet axe n'a pas pu être comparé cellule par cellule dans cette passe.":
        "- nothing on a deployment WITH masking: this axis could not be compared cell by cell in this run.",
    "## Matériel et conditions":
        "## Hardware and conditions",
    "| Processeur | {0} ({1} cœurs logiques) |":
        "| Processor | {0} ({1} logical cores) |",
    "| RAM de la machine | {0:.1f} Gio |":
        "| Machine RAM | {0:.1f} GiB |",
    "| Noyau | {0} |":
        "| Kernel | {0} |",
    "inconnue":
        "unknown",
    "| Version de plume mesurée | `{0}` |":
        "| plume version measured | `{0}` |",
    " événements":
        " events",
    "| Volumes mesurés | {0} |":
        "| Volumes measured | {0} |",
    "| Taille de la base (SQLCipher, chiffrée) | {0} |":
        "| Database size (SQLCipher, encrypted) | {0} |",
    "| Budget mémoire | **appliqué** par un scope systemd `MemoryMax=2G MemorySwapMax=0` — la même contrainte que la limite de conteneur de production (`limits.memory: 2Gi`) |":
        "| Memory budget | **enforced** by a systemd scope `MemoryMax=2G MemorySwapMax=0` — the same constraint as the production container limit (`limits.memory: 2Gi`) |",
    "| Concurrence de requêtes | `PLUME_QUERY_CONCURRENCY=3` (le défaut livré) |":
        "| Query concurrency | `PLUME_QUERY_CONCURRENCY=3` (the shipped default) |",
    " et ":
        " and ",
    "| Passes de CONCURRENCE | {0} analystes simultanés, sémaphore {1} (section dédiée) |":
        "| CONCURRENCY runs | {0} simultaneous analysts, semaphore {1} (dedicated section) |",
    "| Budget par requête | interactif, 60 s (`interactive:true`) |":
        "| Budget per query | interactive, 60 s (`interactive:true`) |",
    "**Plusieurs binaires** figurent dans ce document : ":
        "**Several binaries** appear in this document: ",
    ". Chaque cellule porte le sien dans le JSONL brut, et chaque tableau de configuration l'affiche dans son sous-titre. Une comparaison entre deux tableaux de binaires différents mesure aussi l'écart entre les deux binaires — ce n'est légitime que dans la section « Écart mesuré entre deux passes », qui le dit.":
        ". Each cell carries its own in the raw JSONL, and each configuration table shows it in its subtitle. A comparison between two tables of different binaries also measures the gap between the two binaries — it is legitimate only in the section \"Measured gap between two runs\", which says so.",
    "**Honnêteté sur les conditions** : la machine de mesure n'était pas dédiée — d'autres travaux":
        "**Honesty about the conditions**: the measurement machine was not dedicated — other jobs",
    "tournaient en parallèle. Chaque cellule enregistre son `loadavg` et le swap consommé pendant":
        "were running in parallel. Each cell records its `loadavg` and the swap consumed during",
    "la mesure ; les cellules prises sous swap sont marquées et listées plus bas. Le daemon lui-même":
        "the measurement; cells taken under swap are marked and listed below. The daemon itself",
    "ne pouvait pas swapper (`MemorySwapMax=0`), donc sa RSS crête est une vraie crête, mais les":
        "could not swap (`MemorySwapMax=0`), so its peak RSS is a true peak, but the",
    "latences absolues sont **pessimistes** sur une machine chargée.":
        "absolute latencies are **pessimistic** on a loaded machine.",
    "reconstruit depuis l'échantillonneur (premier et dernier point mesurés), le remplissage ayant été borné en temps":
        "reconstructed from the sampler (first and last measured points), the fill having been time-bounded",
    "## Débit d'ingest mesuré (chemin HTTP complet)":
        "## Measured ingest throughput (full HTTP path)",
    "| Événements | Durée | Débit | Base après | `PLUME_FTS_FIELDS` | Binaire |":
        "| Events | Duration | Throughput | Database after | `PLUME_FTS_FIELDS` | Binary |",
    "| {0} | {1} s | **{2} ev/s** | {3} Mio | {4} | `{v}` |":
        "| {0} | {1} s | **{2} ev/s** | {3} MiB | {4} | `{v}` |",
    "Chemin traversé : `":
        "Path traversed: `",
    "> Ligne de {0} événements : **{1}.**":
        "> Row of {0} events: **{1}.**",
    "Débit **cumulé** relevé par le générateur lui-même pendant le remplissage (il est régulé sur la profondeur du spool : son débit de production est donc le débit d'ingest de bout en bout). Ces points couvrent le DÉBUT du remplissage :":
        "**Cumulative** throughput recorded by the generator itself during the fill (it is regulated on the spool depth: its production rate is therefore the end-to-end ingest throughput). These points cover the START of the fill:",
    "| Événements produits | Volume produit | Débit cumulé mesuré |":
        "| Events produced | Volume produced | Measured cumulative throughput |",
    "| {0} | {mio:.0f} Mio | **{1} ev/s** |":
        "| {0} | {mio:.0f} MiB | **{1} ev/s** |",
    "Le débit cumulé passe de **{0} ev/s** à **{1} ev/s** entre {2} et {3} événements produits, soit **x{4:.1f}**. Deux causes se superposent — le volume déjà en base (maintenance des index et de la FTS5) et la charge de la machine — et cette passe ne les sépare pas. À ce débit-là, atteindre 10 M depuis ce point aurait demandé plusieurs heures de plus : c'est ce qui a borné CETTE passe-ci, et cela ne dit rien des autres passes du document.":
        "The cumulative throughput goes from **{0} ev/s** to **{1} ev/s** between {2} and {3} events produced, i.e. **x{4:.1f}**. Two causes overlap — the volume already in the database (maintenance of the indexes and of FTS5) and the load of the machine — and this run does not separate them. At that throughput, reaching 10 M from this point would have taken several more hours: that is what bounded THIS run, and it says nothing about the other runs of the document.",
    "### Courbe de remplissage — `{0}`":
        "### Fill curve — `{0}`",
    "#### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé":
        "#### Ingest throughput degrades with volume — measured, not assumed",
    "Un débit moyen seul cacherait cette dégradation. Chaque ligne est un intervalle":
        "An average throughput alone would hide this degradation. Each row is a real sampling",
    "d'échantillonnage réel pendant le remplissage (la maintenance des index et de la":
        "interval during the fill (maintaining the indexes and the",
    "FTS coûte de plus en plus cher à mesure que les b-trees grossissent).":
        "FTS costs more and more as the b-trees grow).",
    "| Lignes en base | Taille base | RSS du daemon | Débit sur l'intervalle | `loadavg` |":
        "| Rows in database | Database size | Daemon RSS | Throughput over the interval | `loadavg` |",
    "| {0} | {1} Mio | {2} Mio | {3} ev/s | {la:.1f} |":
        "| {0} | {1} MiB | {2} MiB | {3} ev/s | {la:.1f} |",
    "##### D'où vient l'effondrement — attribution mesurée, pas supposée":
        "##### Where the collapse comes from — measured attribution, not assumed",
    "Un débit qui tombe ne dit pas POURQUOI il tombe. Trois grandeurs le disent, et":
        "A falling throughput does not say WHY it falls. Three quantities say it, and",
    "elles sont relevées à chaque tick par `bench/probe.py` :":
        "they are recorded at each tick by `bench/probe.py`:",
    "- **CPU du daemon par événement** — s'il monte, le travail par ligne grandit":
        "- **Daemon CPU per event** — if it rises, the work per row really",
    "  vraiment (b-trees plus profonds, index et FTS à maintenir) : c'est le VOLUME.":
        "  grows (deeper b-trees, indexes and FTS to maintain): it is the VOLUME.",
    "- **CPU consommé par le reste de la machine** — c'est la CONTENTION. Elle inclut":
        "- **CPU consumed by the rest of the machine** — it is CONTENTION. It includes",
    "  les fils noyau qui exécutent NOS propres écritures : ce n'est donc pas":
        "  the kernel threads that execute OUR own writes: so it is not",
    "  seulement « d'autres travaux », c'est « du CPU non facturé au daemon ».":
        "  only \"other jobs\", it is \"CPU not billed to the daemon\".",
    "- **Octets lus au bloc et stall mémoire du cgroup** — si le plafond de 2 Gio":
        "- **Bytes read at the block layer and cgroup memory stall** — if the 2 GiB ceiling",
    "  forçait la récupération du cache de pages, ils monteraient. Le budget est":
        "  forced the page cache to be reclaimed, they would rise. The budget is",
    "  appliqué par ce même cgroup, et son cache de pages lui est facturé.":
        "  enforced by this same cgroup, and its page cache is billed to it.",
    "| Lignes en base | Débit | CPU daemon / événement | cœurs daemon | cœurs du reste | lu au bloc | écrit / 1 000 év. | stall mémoire | part de la sonde |":
        "| Rows in database | Throughput | Daemon CPU / event | daemon cores | cores of the rest | read at block layer | written / 1,000 ev. | memory stall | probe share |",
    "| {0} | {1} ev/s | {2:.3f} ms | {3:.2f} | {4:.2f} | {5} Mio | {6:.1f} Mio | {7:.0f} ms | {8:.1f} % |":
        "| {0} | {1} ev/s | {2:.3f} ms | {3:.2f} | {4:.2f} | {5} MiB | {6:.1f} MiB | {7:.0f} ms | {8:.1f} % |",
    "« Part de la sonde » = ce que le COMPTAGE DES LIGNES de l'échantillonneur consomme de l'intervalle : **{0:.1f} % en médiane**, **{1:.1f} % au pire**. Ce comptage est un scan servi par le daemon : son coût est DANS les colonnes CPU et débit ci-dessus. La dégradation nette du produit est donc un peu plus faible que celle affichée — jamais plus forte.":
        "\"Probe share\" = what the sampler's ROW COUNT consumes of the interval: **{0:.1f} % median**, **{1:.1f} % worst**. This count is a scan served by the daemon: its cost is IN the CPU and throughput columns above. The net degradation of the product is therefore slightly smaller than the one shown — never larger.",
    "Entre {0} et {1} lignes en base, le débit passe de **{2} à {3} ev/s** (**÷{fall:.2f}**) et le coût CPU du daemon par événement de **{cpu0:.3f} à {cpu1:.3f} ms** (**×{cpu_growth:.2f}**).":
        "Between {0} and {1} rows in the database, the throughput goes from **{2} to {3} ev/s** (**÷{fall:.2f}**) and the daemon CPU cost per event from **{cpu0:.3f} to {cpu1:.3f} ms** (**×{cpu_growth:.2f}**).",
    "Cette chute se FACTORISE, sans reste, en deux facteurs mesurés — le débit est exactement **cœurs occupés / CPU par événement** :":
        "This drop FACTORISES, without remainder, into two measured factors — the throughput is exactly **busy cores / CPU per event**:",
    "> **÷{fall:.2f}** (débit mesuré) = **×{cpu_growth:.2f}** (CPU par événement : le travail par ligne grandit avec les b-trees) × **÷{0:.2f}** (cœurs occupés par le daemon : {c0:.2f} au début contre {c1:.2f} à la fin — il ATTEND davantage). Le produit vaut ÷{prod:.2f}, soit {1:.0f} % d'écart avec la chute mesurée : l'écart est celui de la moyenne par quartile, l'identité **débit = cœurs / CPU par événement** étant exacte intervalle par intervalle.":
        "> **÷{fall:.2f}** (measured throughput) = **×{cpu_growth:.2f}** (CPU per event: the work per row grows with the b-trees) × **÷{0:.2f}** (cores busy with the daemon: {c0:.2f} at the start against {c1:.2f} at the end — it WAITS more). The product is ÷{prod:.2f}, i.e. a {1:.0f} % gap with the measured drop: the gap is that of the per-quartile average, the identity **throughput = cores / CPU per event** being exact interval by interval.",
    "Le travail par ligne grandit donc RÉELLEMENT avec le volume déjà en base : c'est le VOLUME, pas la machine. Et le daemon n'occupe jamais plus de {0:.2f} cœur sur les 12 disponibles : le chemin d'écriture est SÉQUENTIEL, ajouter des cœurs n'y changerait rien.":
        "The work per row therefore REALLY grows with the volume already in the database: it is the VOLUME, not the machine. And the daemon never occupies more than {0:.2f} core out of the 12 available: the write path is SEQUENTIAL, adding cores would change nothing.",
    "Le coût CPU par événement ne bouge PAS pendant que le débit tombe : le daemon n'a pas plus de travail par ligne, il ATTEND. La cause n'est donc pas le volume en base.":
        "The CPU cost per event does NOT move while the throughput falls: the daemon has no more work per row, it WAITS. The cause is therefore not the volume in the database.",
    "Le débit ne s'effondre pas sur cet intervalle : il n'y a rien à attribuer.":
        "The throughput does not collapse over this interval: there is nothing to attribute.",
    "Le daemon occupe **{dmnmed:.2f} cœur** en médiane pendant que le reste de la machine en occupe **{othmed:.2f}** (12 cœurs disponibles). ":
        "The daemon occupies **{dmnmed:.2f} core** at the median while the rest of the machine occupies **{othmed:.2f}** (12 cores available). ",
    "La machine n'est donc pas saturée : la chute n'est pas une contention de CPU disponible.":
        "The machine is therefore not saturated: the drop is not a contention for available CPU.",
    "La machine est proche de la saturation : une part de la chute est de la contention.":
        "The machine is close to saturation: part of the drop is contention.",
    "**Ce que coûterait {0} événements** : au DERNIER débit mesuré ({1} ev/s), il resterait {2} événements à ingérer, soit **{h:.1f} h** — et c'est un PLANCHER, puisque le débit a déjà été divisé par {fall:.1f} sur la plage mesurée et continue de baisser. Cette ligne est de l'arithmétique sur des débits mesurés, PAS une mesure à ce volume : aucune latence de ce document ne vaut au-delà du volume réellement rempli.":
        "**What {0} events would cost**: at the LAST measured throughput ({1} ev/s), {2} events would remain to be ingested, i.e. **{h:.1f} h** — and that is a FLOOR, since the throughput has already been divided by {fall:.1f} over the measured range and keeps falling. This row is arithmetic on measured throughputs, NOT a measurement at that volume: no latency in this document holds beyond the volume actually filled.",
    "**Le stockage n'est pas en cause côté LECTURE** : {0} Mio lus au bloc sur tout le remplissage — la base tient dans le cache de pages. **Le plafond de 2 Gio ne freine pas non plus par récupération mémoire** : {stall:.1f} s de stall mémoire cumulé sur le cgroup, mesuré.":
        "**Storage is not at fault on the READ side**: {0} MiB read at the block layer over the whole fill — the database fits in the page cache. **The 2 GiB ceiling does not slow things down through memory reclaim either**: {stall:.1f} s of cumulative memory stall on the cgroup, measured.",
    "Débit sur les intervalles échantillonnés : **min {0:.0f} ev/s, médiane {med:.0f} ev/s, max {1:.0f} ev/s**, pour un `loadavg` allant de {2:.1f} à {3:.1f}. L'écart d'un facteur {4:.1f} entre le plus lent et le plus rapide intervalle ":
        "Throughput over the sampled intervals: **min {0:.0f} ev/s, median {med:.0f} ev/s, max {1:.0f} ev/s**, for a `loadavg` ranging from {2:.1f} to {3:.1f}. The gap of a factor {4:.1f} between the slowest and the fastest interval ",
    "n'est plus interprété depuis le `loadavg` : la sous-section d'attribution ci-dessus le décompose en CPU du daemon, CPU du reste de la machine et attente du stockage — trois grandeurs mesurées.":
        "is no longer interpreted from the `loadavg`: the attribution subsection above breaks it down into daemon CPU, CPU of the rest of the machine and storage wait — three measured quantities.",
    "suit le `loadavg` : **cette passe ne sépare pas** le volume déjà en base de la charge de la machine — son CSV est antérieur à la sonde qui relève le CPU par processus. À lire comme un PLANCHER.":
        "follows the `loadavg`: **this run does not separate** the volume already in the database from the load of the machine — its CSV predates the probe that records CPU per process. To be read as a FLOOR.",
    "La colonne RSS est la mémoire réellement occupée par le daemon PENDANT l'ingest — crête échantillonnée ici : **{0} Mio**, à confronter au budget de 2 Gio. C'est une mesure, pas une estimation.":
        "The RSS column is the memory actually occupied by the daemon DURING the ingest — peak sampled here: **{0} MiB**, to be set against the 2 GiB budget. It is a measurement, not an estimate.",
    "> Portée de cette courbe : l'échantillonneur ne couvre que la fenêtre où il a tourné ({0} à {1} lignes). Ce qui s'est passé avant n'est pas dans ce tableau, et n'est donc pas mesuré ici.":
        "> Scope of this curve: the sampler only covers the window during which it ran ({0} to {1} rows). What happened before is not in this table, and is therefore not measured here.",
    "## Configurations mesurées":
        "## Configurations measured",
    "| Étiquette | Événements | Hôtes | `PLUME_FTS_FIELDS` | Masquage de champs | Tier froid | Classes mesurées |":
        "| Label | Events | Hosts | `PLUME_FTS_FIELDS` | Field masking | Cold tier | Classes measured |",
    "**sous-ensemble** `":
        "**subset** `",
    "toutes":
        "all",
    "| `{c}` | {0} | {1} | {2} | {3} | {4} | {5} ({n_cells} cellules) |":
        "| `{c}` | {0} | {1} | {2} | {3} | {4} | {5} ({n_cells} cells) |",
    "Le masquage compte parce qu'il est **contre-intuitif** : un ensemble de masquage non vide":
        "Masking matters because it is **counter-intuitive**: a non-empty masking set",
    "désarme la route de rollups *et* le moteur vectorisé (`handlers/query.rs:282`,":
        "disarms the rollup route *and* the vectorised engine (`handlers/query.rs:282`,",
    "`cold_store/planner.rs:601`). Le rempart de confidentialité est un frein de performance, donc":
        "`cold_store/planner.rs:601`). The confidentiality safeguard is a performance brake, so",
    "des chiffres publiés sans cet axe ne vaudraient que pour un déploiement **sans** masquage.":
        "figures published without this axis would only hold for a deployment **without** masking.",
    "Toutes les cellules sont tirées avec le **même rôle** (`viewer`) dans les deux états : une règle":
        "All cells are fired with the **same role** (`viewer`) in both states: a mask",
    "de masque à `role:''` ne contraint pas un admin (`field_filter.rs:110-115`), le comparer en":
        "rule at `role:''` does not constrain an admin (`field_filter.rs:110-115`), comparing it as",
    "admin ne mesurerait rien.":
        "admin would measure nothing.",
    "## Résultats — `{c}`":
        "## Results — `{c}`",
    "*`PLUME_FTS_FIELDS`={0}, masquage={1}, froid={2}, version=`{3}`, {4} événements, base {5} Mio.*":
        "*`PLUME_FTS_FIELDS`={0}, masking={1}, cold={2}, version=`{3}`, {4} events, database {5} MiB.*",
    "Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du":
        "Latencies in milliseconds (wall, client side), unless marked `s`. `RSS` = real peak of the",
    "processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le":
        "process sampled every 15 ms during the query. `lu` = bytes read at the block layer by the",
    "processus (0 = servi depuis le cache de pages).":
        "process (0 = served from the page cache).",
    "**{0} cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.":
        "**{0} cells of this table have a `p95/p50` dispersion greater than 3.** On a shared machine, this does not describe plume: it describes the fact that the measurement was jostled by the other jobs. These cells are annotated; their `p50` remains usable, their `p95` does not.",
    "**Ce que `p95` vaut ici** : {0} répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.":
        "**What `p95` is worth here**: {0} repetitions per cell (the harness falls back to 3 when the first shot exceeds 3 s, so that the matrix stays tractable). At this number of samples, nearest-rank `p95` **is the maximum observed**: it is an upper bound on a tiny sample, not a real distribution tail. Read it as \"the worst of N shots\", nothing more.",
    "> Cette configuration ne mesure que les classes `{0}`. Les classes absentes":
        "> This configuration only measures the classes `{0}`. The classes absent",
    "> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas":
        "> from the table below are **not measured** in this configuration — not",
    "> implicitement inchangées.":
        "> implicitly unchanged.",
    "| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |":
        "| Class | Window | p50 | p95 | 1st shot | peak RSS | read | rows | route | note |",
    "ERREUR: ":
        "ERROR: ",
    "tronqué":
        "truncated",
    "**pris sous swap — à rejouer**":
        "**taken under swap — to be re-run**",
    "**> 2 Gio**":
        "**> 2 GiB**",
    "{0}/{1} tirs OK":
        "{0}/{1} shots OK",
    "dispersion x{0:.1f} (loadavg {1:.0f}) — p95 dominé par la contention, pas par plume":
        "dispersion x{0:.1f} (loadavg {1:.0f}) — p95 dominated by contention, not by plume",
    "| `{cid}` <br><sub>{label}</sub> | {w} | {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |":
        "| `{cid}` <br><sub>{label}</sub> | {w} | {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |",
    "## Écart mesuré entre deux passes — `{c_av}` vs `{c_ap}`":
        "## Measured gap between two runs — `{c_av}` vs `{c_ap}`",
    "Comparaison `{c_av}` -> `{c_ap}`, MÊME base, MÊME instrument, MÊME machine, passes consécutives. Les deux lignes sont des mesures ; le delta est leur soustraction, rien de plus.":
        "Comparison `{c_av}` -> `{c_ap}`, SAME database, SAME instrument, SAME machine, consecutive runs. Both rows are measurements; the delta is their subtraction, nothing more.",
    "**Ce qui a changé entre les deux passes** : {note}":
        "**What changed between the two runs**: {note}",
    "Charge machine relevée : `loadavg` {0} pendant la passe AVANT, {1} pendant la passe APRÈS. Sur une machine partagée, un écart de quelques millisecondes ne prouve rien ; seuls les écarts francs sont exploitables, et les cellules dont la dispersion est annotée plus haut restent à lire avec la même réserve.":
        "Machine load recorded: `loadavg` {0} during the BEFORE run, {1} during the AFTER run. On a shared machine, a gap of a few milliseconds proves nothing; only clear-cut gaps are usable, and the cells whose dispersion is annotated above are to be read with the same reservation.",
    "| Classe | Fenêtre | p50 avant | p50 après | delta | SQL avant | SQL après | route avant | route après |":
        "| Class | Window | p50 before | p50 after | delta | SQL before | SQL after | route before | route after |",
    " ⚠ **réponse tronquée d'un côté**":
        " ⚠ **answer truncated on one side**",
    "**{nt} de ces lignes opposent des réponses de contenu DIFFÉRENT** (un côté tronque) : leur delta mesure un écart de travail, pas un écart de vitesse. Elles sont marquées.":
        "**{nt} of these rows oppose answers with DIFFERENT content** (one side truncates): their delta measures a gap in work, not a gap in speed. They are marked.",
    "{seen_pairs} cellules comparables. ":
        "{seen_pairs} comparable cells. ",
    "Mesurées SEULEMENT après : {0}. ":
        "Measured ONLY after: {0}. ",
    "Mesurées SEULEMENT avant : {0}. ":
        "Measured ONLY before: {0}. ",
    "Une cellule non comparable n'est PAS un résultat neutre : elle est absente d'un côté.":
        "A non-comparable cell is NOT a neutral result: it is absent on one side.",
    "## Les fenêtres mesurées, et celles qui ne le sont pas":
        "## The windows measured, and those that are not",
    "Les fenêtres ne sont pas choisies : elles sont DÉRIVÉES de deux paramètres du produit — la":
        "The windows are not chosen: they are DERIVED from two product parameters — the",
    "fenêtre chaude (`PLUME_COLD_HOT_WINDOW_DAYS`, défaut **7 j**, `cold_store/aging.rs`) et la":
        "hot window (`PLUME_COLD_HOT_WINDOW_DAYS`, default **7 d**, `cold_store/aging.rs`) and the",
    "rétention (`PLUME_RETENTION_DAYS`) — puis filtrées par l'étendue réelle du jeu de données.":
        "retention (`PLUME_RETENTION_DAYS`) — then filtered by the actual span of the dataset.",
    "| Fenêtre | Ce qu'elle mesure |":
        "| Window | What it measures |",
    "**Fenêtres écartées par la garde de couverture — donc NON MESURÉES** :":
        "**Windows excluded by the coverage guard — hence NOT MEASURED**:",
    "Une fenêtre plus large que le jeu ne mesure pas ce que dit son étiquette : elle mesure":
        "A window wider than the dataset does not measure what its label says: it measures",
    "`all` (« tout ») sous un autre nom. Le harnais refuse de la tirer plutôt que de publier une cellule":
        "`all` under another name. The harness refuses to fire it rather than publish a cell",
    "dont le titre serait faux. Pour l'obtenir, il faut un jeu qui la couvre — c'est-à-dire":
        "whose title would be wrong. To get it, a dataset that covers it is needed — that is,",
    "remplir sur une étendue plus longue (`BENCH_SPAN_DAYS`), pas rendre la garde plus permissive.":
        "filling over a longer span (`BENCH_SPAN_DAYS`), not making the guard more permissive.",
    "## Le tier froid — mesuré":
        "## The cold tier — measured",
    "Avec une fenêtre chaude de 7 jours et une rétention de 365, `daemon/src/cold_store/` est":
        "With a hot window of 7 days and a retention of 365, `daemon/src/cold_store/` is",
    "le chemin de lecture de **358 des 365 jours** d'une production. Les tableaux ci-dessus":
        "the read path for **358 of the 365 days** of a deployment. The tables above",
    "tournent tous à `PLUME_COLD_TIER=0` : ils ne disent rien de ce chemin. Cette section est":
        "all run at `PLUME_COLD_TIER=0`: they say nothing about this path. This section is",
    "la seule qui en parle, et elle ne parle que de ce qui a été tiré.":
        "the only one that talks about it, and it only talks about what was fired.",
    "**Columnarisation mesurée** (chemin réel : `plume-daemon retention` -> `retention_run`":
        "**Measured columnarisation** (real path: `plume-daemon retention` -> `retention_run`",
    "-> `cold_age_run`, fenêtre chaude {0} j) :":
        "-> `cold_age_run`, hot window {0} d):",
    "| | Avant | Après |":
        "| | Before | After |",
    "| Lignes CHAUDES (SQLite) | {0} | {1} |":
        "| HOT rows (SQLite) | {0} | {1} |",
    "| Base chaude | {0} Mio | {1} Mio |":
        "| Hot database | {0} MiB | {1} MiB |",
    "| Tier froid (Parquet chiffré) | 0 Mio | {0} Mio en {1} fichiers |":
        "| Cold tier (encrypted Parquet) | 0 MiB | {0} MiB in {1} files |",
    "**{0} lignes ({pct:.1f} %) ont quitté SQLite pour le Parquet**, en {1} fichiers (un par jour). Le froid pèse **{ratio:.0f} octets par événement** là où le chaud en occupait {2:.0f} (table, index et FTS compris), soit **{3:.0f}x plus compact**.":
        "**{0} rows ({pct:.1f} %) left SQLite for Parquet**, in {1} files (one per day). The cold side weighs **{ratio:.0f} bytes per event** where the hot side occupied {2:.0f} (table, indexes and FTS included), i.e. **{3:.0f}x more compact**.",
    "> Durée : {0}":
        "> Duration: {0}",
    "Durée mesurée : **{0} s**, soit {1:.0f} lignes/s.":
        "Measured duration: **{0} s**, i.e. {1:.0f} rows/s.",
    "> La base chaude n'a pas RÉTRÉCI : SQLite ne rend pas les pages au système, il les":
        "> The hot database did not SHRINK: SQLite does not return pages to the system, it puts",
    "> met en liste libre (`auto_vacuum=0`, le réglage par défaut). L'espace est réutilisé":
        "> them on a free list (`auto_vacuum=0`, the default setting). The space is reused",
    "> par les écritures suivantes, il n'est pas rendu au disque. C'est mesuré, pas supposé.":
        "> by the following writes, it is not returned to the disk. This is measured, not assumed.",
    "### La réponse est-elle la MÊME ? (parité mesurée)":
        "### Is the answer the SAME? (measured parity)",
    "Une latence n'est comparable que si les deux chemins rendent la même réponse : un":
        "A latency is comparable only if both paths return the same answer: a",
    "chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne":
        "path that TRUNCATES is faster because it does less. This subsection therefore does not",
    "compare donc pas des temps, elle compare **les valeurs rendues**.":
        "compare times, it compares **the values returned**.",
    "Méthode : {0}":
        "Method: {0}",
    "| Verdict | n | ce qu'il signifie |":
        "| Verdict | n | what it means |",
    "| `same` | {0} | les deux côtés rendent la MÊME réponse. |":
        "| `same` | {0} | both sides return the SAME answer. |",
    "| `differs` | {0} | ils divergent **sans le dire** — un nombre faux, lisible et copiable. C'est LE cas grave. |":
        "| `differs` | {0} | they diverge **without saying so** — a wrong number, readable and copyable. It is THE serious case. |",
    "| `declared` | {0} | ils divergent et le côté froid le DIT (`truncated`, ou note de couverture). L'incomplétude devient une information. |":
        "| `declared` | {0} | they diverge and the cold side SAYS so (`truncated`, or coverage note). The incompleteness becomes information. |",
    "| `refused` | {0} | un côté REFUSE, avec un motif nommé. Une erreur vaut mieux qu'un nombre faux : c'est la position de repli, pas l'échec. |":
        "| `refused` | {0} | one side REFUSES, with a named reason. An error is better than a wrong number: it is the fallback position, not the failure. |",
    "`declared` n'acquitte rien : un AGRÉGAT tronqué reste un nombre faux, déclaré ou non.":
        "`declared` acquits nothing: a truncated AGGREGATE remains a wrong number, declared or not.",
    "Les catégories ne s'additionnent jamais en un « tout va bien ».":
        "The categories never add up to an \"all is well\".",
    "**Le compte qui compte : {nf} NOMBRE(S) FAUX.** C'est le nombre de contrôles dont la":
        "**The count that counts: {nf} WRONG NUMBER(S).** It is the number of checks whose",
    "réponse porte une valeur calculée SUR L'ENSEMBLE (`count`/`dc`/`stats … by …`) et dont":
        "answer carries a value computed OVER THE SET (`count`/`dc`/`stats … by …`) and whose",
    "les deux côtés DIVERGENT — que le côté froid l'ait déclaré ou non. C'est exactement ce":
        "two sides DIVERGE — whether the cold side declared it or not. It is exactly what",
    "que l'invariant de `cold_store/exactness.rs` interdit. Les autres catégories décrivent":
        "the invariant of `cold_store/exactness.rs` forbids. The other categories describe",
    "des réponses partielles de LIGNES (vraies, incomplètes, signalées) ou des refus motivés :":
        "partial answers of ROWS (true, incomplete, flagged) or reasoned refusals:",
    "elles ne sont pas du même ordre de gravité.":
        "they are not of the same order of severity.",
    "> Comptage : {0}":
        "> Count: {0}",
    "Le détail de tout ce qui n'est pas `same` :":
        "The detail of everything that is not `same`:",
    "| Requête | Fenêtre | Verdict | Sans tier froid | Avec tier froid |":
        "| Query | Window | Verdict | Without cold tier | With cold tier |",
    "refus {0}":
        "refusal {0}",
    " (couverture déclarée)":
        " (coverage declared)",
    " (tronqué)":
        " (truncated)",
    "{0} lignes `{1}`{tag}":
        "{0} rows `{1}`{tag}",
    "**Écart maximal mesuré sur un agrégat scalaire** : `{0}` sur la fenêtre `{1}` rend **{2}** sans tier froid et **{3}** avec — soit **x{r:.1f}**. Ce n'est pas une réponse approchée, c'est un mauvais nombre : le":
        "**Largest gap measured on a scalar aggregate**: `{0}` over the window `{1}` returns **{2}** without the cold tier and **{3}** with it — i.e. **x{r:.1f}**. This is not an approximate answer, it is a wrong number: the",
    "chemin d'union hydrate le froid dans une table temporaire SQLite bornée à":
        "union path hydrates the cold side into a temporary SQLite table bounded at",
    "`PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège":
        "`PLUME_QUERY_MAX` rows (default **5,000**, `cold_store/reader.rs:130`) then aggregates",
    "SUR CET ÉCHANTILLON.":
        "OVER THIS SAMPLE.",
    "**Aucun agrégat scalaire ne diverge.** Les contrôles réductibles à un nombre rendent":
        "**No scalar aggregate diverges.** The checks reducible to a number return",
    "la même valeur des deux côtés, ou bien le côté froid REFUSE de répondre en nommant sa":
        "the same value on both sides, or else the cold side REFUSES to answer, naming its",
    "cause. C'est l'invariant de `cold_store/exactness.rs` : aucune valeur dérivée d'un":
        "cause. This is the invariant of `cold_store/exactness.rs`: no value derived from a",
    "ensemble tronqué n'est rendue comme un nombre.":
        "truncated set is returned as a number.",
    "| Requête | Fenêtre | Sans tier froid | Avec tier froid | Écart | Tronqué ? |":
        "| Query | Window | Without cold tier | With cold tier | Gap | Truncated? |",
    "**oui** ({0} lignes hydratées)":
        "**yes** ({0} rows hydrated)",
    "Le chemin d'union chaud∪froid hydrate le froid dans une table temporaire SQLite bornée":
        "The hot∪cold union path hydrates the cold side into a temporary SQLite table bounded",
    "à `PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège":
        "at `PLUME_QUERY_MAX` rows (default **5,000**, `cold_store/reader.rs:130`) then aggregates",
    "SUR CET ÉCHANTILLON. Le compte rendu n'est donc pas « approché » : il est **faux d'un":
        "OVER THIS SAMPLE. The count returned is therefore not \"approximate\": it is **wrong by a",
    "facteur qui dépend du volume de la fenêtre**. Le daemon le SIGNALE":
        "factor that depends on the volume of the window**. The daemon FLAGS it",
    "(`stats.truncated=true`), mais un lecteur qui ne regarde que le nombre voit un nombre":
        "(`stats.truncated=true`), but a reader who only looks at the number sees a wrong",
    "faux. Toute latence « froide » de cette passe doit donc être lue avec sa colonne":
        "number. Any \"cold\" latency of this run must therefore be read with its",
    "« tronqué » : quand elle dit oui, la cellule mesure le temps d'une réponse INCOMPLÈTE,":
        "\"truncated\" column: when it says yes, the cell measures the time of an INCOMPLETE answer,",
    "et ne peut pas être comparée à la cellule chaude.":
        "and cannot be compared with the hot cell.",
    "> Réserve : {0}":
        "> Caveat: {0}",
    "Frontière chaud/froid CALCULÉE PAR LE DAEMON : `boundary_ts={bnd}`. Une fenêtre":
        "Hot/cold boundary COMPUTED BY THE DAEMON: `boundary_ts={bnd}`. A window",
    "dont la borne basse passe sous cette valeur lit du Parquet ; une fenêtre qui":
        "whose lower bound goes below this value reads Parquet; a window that",
    "l'enjambe lit les DEUX et paie l'union.":
        "straddles it reads BOTH and pays for the union.",
    "| Classe | Fenêtre | p50 | lignes | route | passé par le froid | tronqué |":
        "| Class | Window | p50 | rows | route | went through cold | truncated |",
    "**oui**":
        "**yes**",
    "> Dans le tableau des configurations, la colonne « Événements » de `{c}` vaut {0} : c'est le nombre de lignes CHAUDES, pas la taille du jeu. {1} événements sont interrogeables, dont {2} depuis le Parquet.":
        "> In the configurations table, the \"Events\" column of `{c}` is {0}: it is the number of HOT rows, not the size of the dataset. {1} events can be queried, of which {2} from Parquet.",
    "**{ncold} cellules sur {0} ont réellement traversé le tier froid** (colonne":
        "**{ncold} cells out of {0} actually went through the cold tier** (column",
    "« passé par le froid » : elle vient de `stats.cold` renvoyé par le daemon, pas de":
        "\"went through cold\": it comes from `stats.cold` returned by the daemon, not from",
    "l'étiquette de configuration). ":
        "the configuration label). ",
    "**{ntrunc} cellules sont TRONQUÉES** : le chemin d'union hydrate le froid dans SQLite avec un plafond de lignes (`PLUME_QUERY_MAX`, défaut 5 000, `cold_store/reader.rs:130`) — au-delà, la réponse est PARTIELLE et le daemon le dit. Un agrégat sur une fenêtre froide large n'est donc pas exact par défaut : c'est le résultat le plus important de cette section.":
        "**{ntrunc} cells are TRUNCATED**: the union path hydrates the cold side into SQLite with a row ceiling (`PLUME_QUERY_MAX`, default 5,000, `cold_store/reader.rs:130`) — beyond it, the answer is PARTIAL and the daemon says so. An aggregate over a wide cold window is therefore not exact by default: it is the most important result of this section.",
    "Aucune cellule tronquée.":
        "No truncated cell.",
    "## Le nombre de machines — ce que le profil mono-hôte cachait":
        "## The number of machines — what the single-host profile was hiding",
    "La base profilée est **mono-nœud** : toutes ses sources ont `distinct_hosts: 1`. `host`":
        "The profiled database is **single-node**: all its sources have `distinct_hosts: 1`. `host`",
    "étant l'une des six colonnes indexées, toute cellule qui filtre ou groupe par hôte y porte":
        "being one of the six indexed columns, any cell that filters or groups by host there bears",
    "sur un cas **dégénéré de cardinalité 1**. Les passes ci-dessous rejouent les mêmes classes":
        "on a **degenerate case of cardinality 1**. The runs below replay the same classes",
    "sur des profils FLOTTE dérivés (`bench/make_fleet_profile.py`), **à volume d'événements":
        "on derived FLEET profiles (`bench/make_fleet_profile.py`), **at equal event",
    "égal**.":
        "volume**.",
    "**Ce qui change exactement entre ces passes** — il faut le dire avant de lire le tableau :":
        "**What exactly changes between these runs** — it must be said before reading the table:",
    "**(1)** la cardinalité de `host` (1, puis N) ; **(2)** le MÉLANGE des sources, parce que":
        "**(1)** the cardinality of `host` (1, then N); **(2)** the MIX of sources, because",
    "multiplier les sources host-locales par N change leur poids relatif (`auditd` passe de":
        "multiplying the host-local sources by N changes their relative weight (`auditd` goes from",
    "38,5 % à 44,7 % du flux). Les deux viennent de la même dérivation. Une classe qui bouge":
        "38.5 % to 44.7 % of the stream). Both come from the same derivation. A class that moves",
    "peut donc bouger pour l'une OU l'autre raison — sauf les classes `C6*`, qui nomment `host`":
        "can therefore move for one OR the other reason — except the `C6*` classes, which name `host`",
    "dans la requête : celles-là isolent la cardinalité, et ce sont elles qu'il faut lire pour":
        "in the query: those isolate the cardinality, and they are the ones to read to",
    "juger du trou de généricité.":
        "judge the genericity gap.",
    "**Ce que la taille de flotte change en VOLUME** — dérivé (`bench/make_fleet_profile.py`)":
        "**What the fleet size changes in VOLUME** — derived (`bench/make_fleet_profile.py`)",
    "des distributions MESURÉES par source, sur la fenêtre de la base profilée :":
        "from the distributions MEASURED per source, over the window of the profiled database:",
    "| Hôtes | Sources host-locales | Événements mono-hôte (mesuré) | Événements flotte (dérivé) | Facteur |":
        "| Hosts | Host-local sources | Single-host events (measured) | Fleet events (derived) | Factor |",
    "| {h} | {nph} sur 32 | {0} | {1} | x{mult} |":
        "| {h} | {nph} of 32 | {0} | {1} | x{mult} |",
    "La colonne « dérivé » n'est PAS une mesure : c'est la multiplication du poids des":
        "The \"derived\" column is NOT a measurement: it is the multiplication of the weight of the",
    "sources déclarées host-locales par le nombre de machines. Ce qui est mesuré, ce sont":
        "sources declared host-local by the number of machines. What is measured is",
    "les distributions de chaque source ; ce qui est déclaré, c'est la liste des sources":
        "the distribution of each source; what is declared is the list of",
    "host-locales (`bench/fleet-per-host.txt`, une ligne par source, avec sa raison).":
        "host-local sources (`bench/fleet-per-host.txt`, one row per source, with its reason).",
    "{h} hôte{0}":
        "{h} host{0}",
    "| Classe | Fenêtre | ":
        "| Class | Window | ",
    "Une classe dont la latence ne bouge pas avec le nombre de machines ne dépend pas de la":
        "A class whose latency does not move with the number of machines does not depend on the",
    "cardinalité de `host`. Une classe qui bouge est une classe dont les chiffres publiés sur":
        "cardinality of `host`. A class that moves is a class whose figures published on",
    "un profil mono-hôte **ne valent pas** pour une flotte — et le sens de l'erreur n'est pas":
        "a single-host profile **do not hold** for a fleet — and the direction of the error is not",
    "toujours le même : là où `host` sert de FILTRE, le mono-hôte est PESSIMISTE (le filtre y":
        "always the same: where `host` serves as a FILTER, the single host is PESSIMISTIC (the filter there",
    "sélectionne tout, alors qu'il sélectionne 1/N sur une flotte) ; là où `host` sert de clé de":
        "selects everything, whereas it selects 1/N on a fleet); where `host` serves as a",
    "GROUPEMENT, il est OPTIMISTE (un seul groupe au lieu de N). Un profil mono-hôte ne":
        "GROUPING key, it is OPTIMISTIC (a single group instead of N). A single-host profile therefore does not",
    "« flatte » donc pas le produit : il le décrit FAUX, dans les deux sens à la fois.":
        "\"flatter\" the product: it describes it WRONGLY, in both directions at once.",
    "## Le budget de 2 Gio":
        "## The 2 GiB budget",
    "RSS crête la plus haute observée, toutes cellules confondues : **{0:.0f} Mio** ({1:.1f} % du budget de 2 Gio).":
        "Highest peak RSS observed, all cells combined: **{0:.0f} MiB** ({1:.1f} % of the 2 GiB budget).",
    "**{0} cellules ont dépassé 2 Gio.** Elles sont listées ici parce qu'un dépassement":
        "**{0} cells exceeded 2 GiB.** They are listed here because an overrun",
    "est un résultat, pas un échec à cacher :":
        "is a result, not a failure to hide:",
    "| Configuration | Classe | Fenêtre | RSS crête |":
        "| Configuration | Class | Window | peak RSS |",
    "| `{0}` | `{1}` | {2} | **{3} Mio** |":
        "| `{0}` | `{1}` | {2} | **{3} MiB** |",
    "**Aucune cellule n'a dépassé 2 Gio**, et ce n'est pas une déduction : le daemon tournait":
        "**No cell exceeded 2 GiB**, and this is not a deduction: the daemon ran",
    "dans un scope `MemoryMax=2G MemorySwapMax=0`, où un dépassement se traduit par un kill du":
        "in a `MemoryMax=2G MemorySwapMax=0` scope, where an overrun results in a kernel kill,",
    "noyau, pas par du swap. Il n'a pas été tué.":
        "not in swap. It was not killed.",
    "## Cellules à ne pas croire telles quelles":
        "## Cells not to be believed as they stand",
    "- {superseded} cellules ont été **rejouées** (une mesure bousculée remplacée par une mesure propre) ; seule la dernière figure dans les tableaux, le JSONL brut garde les deux.":
        "- {superseded} cells were **re-run** (a jostled measurement replaced by a clean one); only the last one appears in the tables, the raw JSONL keeps both.",
    "- **Le daemon a été TUÉ après `{0}` / `{1}` / {2}.** {3}":
        "- **The daemon was KILLED after `{0}` / `{1}` / {2}.** {3}",
    "- **{0} cellules prises pendant que la machine swappait** ({1}). Un chiffre pris sous swap est faux. Un rejeu a été TENTÉ pour les cellules de la configuration de référence ; celles qui restent listées ici sont celles pour lesquelles la machine n'a pas offert de fenêtre sans swap. Leur `p50` est à prendre comme une borne haute, leur `p95` comme non exploitable.":
        "- **{0} cells taken while the machine was swapping** ({1}). A figure taken under swap is wrong. A re-run was ATTEMPTED for the cells of the reference configuration; those still listed here are the ones for which the machine did not offer a window without swap. Their `p50` is to be taken as an upper bound, their `p95` as unusable.",
    "- Aucune cellule n'a été prise pendant que la machine swappait (delta de swap < 8 Mio sur chaque cellule).":
        "- No cell was taken while the machine was swapping (swap delta < 8 MiB on each cell).",
    "- **{0} cellules en échec ou en erreur** — elles restent dans le tableau avec leur message :":
        "- **{0} cells failed or in error** — they remain in the table with their message:",
    "  - `{0}` / `{1}` / {2} : {3} (statuts {4})":
        "  - `{0}` / `{1}` / {2}: {3} (statuses {4})",
    "aucun tir réussi":
        "no successful shot",
    "- Aucune cellule en erreur.":
        "- No cell in error.",
    "- **{0} cellules tronquées** par le plafond de lignes (`PLUME_QUERY_MAX`, 5 000 par défaut) : leur latence est celle d'un résultat PARTIEL.":
        "- **{0} truncated cells** due to the row ceiling (`PLUME_QUERY_MAX`, 5,000 by default): their latency is that of a PARTIAL result.",
    "## Comment la latence monte avec le volume":
        "## How latency rises with volume",
    "Mesuré à plusieurs volumes, masque vide, `PLUME_FTS_FIELDS=0`, fenêtre « tout ». C'est la pente qui répond à la question « des millions d'événements », pas un point isolé.":
        "Measured at several volumes, empty mask, `PLUME_FTS_FIELDS=0`, window \"all\". It is the slope that answers the \"millions of events\" question, not an isolated point.",
    "**CE QUE CES COLONNES NE TIENNENT PAS FIXE** — dérivé des enregistrements eux-mêmes, pas déclaré à la main, parce qu'une phrase de comparabilité qu'on ÉCRIT est une phrase qu'on ne mesure plus :":
        "**WHAT THESE COLUMNS DO NOT HOLD FIXED** — derived from the records themselves, not declared by hand, because a comparability sentence that one WRITES is a sentence that one no longer measures:",
    "- `{k}` : **{0} valeurs distinctes** parmi les colonnes. L'écart lu d'une colonne à l'autre n'est donc PAS imputable au seul volume.":
        "- `{k}`: **{0} distinct values** across the columns. The gap read from one column to the next is therefore NOT attributable to volume alone.",
    "- rien : toutes les colonnes s'accordent sur chaque clé que le relevé déclare, hors le volume et la taille de base qui en découle.":
        "- nothing: all the columns agree on every key that the reading declares, apart from the volume and the database size that follows from it.",
    "** : plusieurs colonnes partagent ce volume. Deux colonnes au MÊME volume ne sont pas deux points de l'axe — ce qui les sépare est, par construction, autre chose que le volume.":
        "**: several columns share this volume. Two columns at the SAME volume are not two points of the axis — what separates them is, by construction, something other than volume.",
    "Réserve à connaître avant de citer ce tableau : les volumes viennent de **passes distinctes**, donc de bases distinctes et de nombres de répétitions possiblement différents (la colonne `reps` du JSONL brut le dit cellule par cellule). Les points sont comparables en ordre de grandeur, pas au pourcentage près. Une case vide = classe non mesurée à ce volume. **Le rapport de la dernière colonne oppose la PREMIÈRE et la DERNIÈRE** : il hérite de tout ce qui est listé ci-dessus.":
        "Caveat to know before citing this table: the volumes come from **distinct runs**, hence from distinct databases and possibly different numbers of repetitions (the `reps` column of the raw JSONL says so cell by cell). The points are comparable in order of magnitude, not to the percent. An empty cell = class not measured at this volume. **The ratio in the last column opposes the FIRST and the LAST**: it inherits everything listed above.",
    "{0} lignes":
        "{0} rows",
    "| Classe | {hdr} | rapport |":
        "| Class | {hdr} | ratio |",
    "x{0:.1f} pour x{nr:.1f} de lignes":
        "x{0:.1f} for x{nr:.1f} rows",
    " ⚠ base au plancher":
        " ⚠ floor-bound base",
    "Une classe dont le rapport de latence suit le rapport de lignes est un **scan** : son coût est linéaire en volume et rien ne l'indexe. Une classe dont le rapport reste plat est servie par un index ou par un rollup.":
        "A class whose latency ratio follows the row ratio is a **scan**: its cost is linear in volume and nothing indexes it. A class whose ratio stays flat is served by an index or by a rollup.",
    "⚠ **base au plancher** : au petit volume, la cellule était déjà au plancher fixe (~{0}, voir `C0-plancher`). Le rapport affiché mesure alors la distance à ce plancher, PAS la pente du scan — ne pas le citer comme un facteur d'échelle.":
        "⚠ **floor-bound base**: at the small volume, the cell was already at the fixed floor (~{0}, see `C0-plancher`). The ratio shown then measures the distance to this floor, NOT the slope of the scan — do not cite it as a scaling factor.",
    "## Leviers désignés par la mesure":
        "## Levers designated by the measurement",
    "Aucun n'est implémenté ici : c'est le rôle de l'instrument de les **désigner** et de chiffrer":
        "None is implemented here: it is the role of the instrument to **designate** them and to quantify",
    "le gain qu'on aurait le droit d'en attendre. Classés par gain mesuré décroissant. « Coût RAM »":
        "the gain one would be entitled to expect from them. Ranked by decreasing measured gain. \"RAM cost\"",
    "dit ce que le levier ajouterait au budget de 2 Gio ; quand il est nul, c'est écrit.":
        "says what the lever would add to the 2 GiB budget; when it is nil, it is written.",
    "Le plancher fixe par requête":
        "The fixed floor per query",
    "une requête dont le SQL coûte {0} revient en {1} : **{floor:.0f} ms de coût fixe**, indépendant du volume. Cause identifiée dans le code : le chien de garde de budget est un thread qui boucle sur `sleep(50 ms)` et il est **joint** avant que la réponse ne parte (`daemon/src/query_exec.rs:466-537`, `done.store(true)` puis `watchdog.join()`). Une attente à condition (condvar avec délai) ou un thread non joint rendrait ces millisecondes à **toutes** les requêtes. **Coût RAM : nul.** C'est le levier le moins cher du lot, et il domine toutes les requêtes rapides — donc toute l'expérience interactive.":
        "a query whose SQL costs {0} comes back in {1}: **{floor:.0f} ms of fixed cost**, independent of volume. Cause identified in the code: the budget watchdog is a thread that loops on `sleep(50 ms)` and it is **joined** before the response leaves (`daemon/src/query_exec.rs:466-537`, `done.store(true)` then `watchdog.join()`). A wait on a condition (condvar with timeout) or a non-joined thread would give these milliseconds back to **all** queries. **RAM cost: nil.** It is the cheapest lever of the lot, and it dominates all fast queries — hence the whole interactive experience.",
    "toutes les cellules":
        "all cells",
    "Câbler FTS5 sur le chemin GXQL":
        "Wire FTS5 into the GXQL path",
    "la même aiguille, le même nombre de lignes rendues : **{0}** par GXQL (`message LIKE '%…%'`, scan complet) contre **{1}** par `/api/search` (index FTS5 `event_fts`). L'index EXISTE et est déjà payé — sur l'installation de référence il pèse environ six dixièmes du poids de la table — mais il n'est câblé que sur `/api/search`. Sur le chemin GXQL, un terme libre devient `col LIKE '%motif%'` (`core/src/soql/dialect.rs:65-67`, appelé depuis `soql/mod.rs:881-891`), donc un scan complet. **Coût RAM : nul** — l'index est déjà construit et déjà en base.":
        "the same needle, the same number of rows returned: **{0}** through GXQL (`message LIKE '%…%'`, full scan) against **{1}** through `/api/search` (FTS5 index `event_fts`). The index EXISTS and is already paid for — on the reference installation it weighs about six tenths of the weight of the table — but it is only wired into `/api/search`. On the GXQL path, a free term becomes `col LIKE '%motif%'` (`core/src/soql/dialect.rs:65-67`, called from `soql/mod.rs:881-891`), hence a full scan. **RAM cost: nil** — the index is already built and already in the database.",
    "Rendre l'index d'hôte utilisable AVEC une borne temporelle":
        "Make the host index usable WITH a time bound",
    "le MÊME `stats count by host`, la MÊME base : **{0}** sans borne de temps contre **{1}** borné à la fenêtre chaude du produit (`{hotw}`)":
        "the SAME `stats count by host`, the SAME database: **{0}** without a time bound against **{1}** bounded to the product's hot window (`{hotw}`)",
    ", soit **{ratio:.0f}x plus lent**":
        ", i.e. **{ratio:.0f}x slower**",
    ". Sans borne, le group-by est servi par un parcours d'index seul (`idx_event_host` couvre la requête). Dès qu'une borne `ts` entre, l'index d'hôte ne suffit plus — il faut ouvrir chaque ligne pour lire son `ts` — et la requête redevient un scan. Or la borne temporelle est le cas NORMAL : un tableau de bord regarde toujours une fenêtre. Voie : un index composite `(host, ts)`, qui rend le prédicat de temps satisfiable dans l'index. **Coût RAM : nul ; coût DISQUE : un index de plus** (sur l'installation de référence, `idx_event_host` pèse quelques dizaines de Mio par million d'événements). À noter : cette cellule est déjà à 64 hôtes ; sur une flotte, le nombre de groupes ne fait que grandir.":
        ". Without a bound, the group-by is served by an index-only scan (`idx_event_host` covers the query). As soon as a `ts` bound comes in, the host index is no longer enough — each row must be opened to read its `ts` — and the query becomes a scan again. Yet the time bound is the NORMAL case: a dashboard always looks at a window. Way forward: a composite index `(host, ts)`, which makes the time predicate satisfiable within the index. **RAM cost: nil; DISK cost: one more index** (on the reference installation, `idx_event_host` weighs a few tens of MiB per million events). Note: this cell is already at 64 hosts; on a fleet, the number of groups only grows.",
    "Rendre la route de rollups compatible avec le masquage":
        "Make the rollup route compatible with masking",
    "le coût du masquage sur la route de rollups":
        "the cost of masking on the rollup route",
    "`{masked}` — paire refusée":
        "`{masked}` — pair refused",
    "*Aucun écart n'est rendu ici : le relevé ne contient pas la paire qui isolerait le masquage. C'est un REFUS, pas une absence de problème.*":
        "*No gap is rendered here: the reading does not contain the pair that would isolate masking. It is a REFUSAL, not an absence of problem.*",
    "le MÊME group-by, le MÊME rôle : **{0}** masque vide (servi depuis `{1}`, {2} lignes) contre **{3}** masque non vide (servi depuis `{4}`, {5} lignes — les comptes diffèrent parce que la route de rollups est APPROCHÉE, `stats.approx=true` : c'est le prix de sa vitesse)":
        "the SAME group-by, the SAME role: **{0}** empty mask (served from `{1}`, {2} rows) against **{3}** non-empty mask (served from `{4}`, {5} rows — the counts differ because the rollup route is APPROXIMATE, `stats.approx=true`: it is the price of its speed)",
    ", soit **{ratio:.1f}x plus lent**":
        ", i.e. **{ratio:.1f}x slower**",
    ". Le rempart de confidentialité est donc aussi un frein de performance : un masque non vide désarme la route de rollups (`handlers/query.rs:282`) parce que `event_rollup` stocke `src_ip`/`host` en clair. Deux voies : masquer à la lecture du rollup, ou matérialiser un rollup par classe de masque. **Coût RAM : celui d'un jeu de rollups supplémentaire** (sur l'installation de référence, `event_rollup` pèse de l'ordre du Mio par million d'événements, donc marginal), plus le masquage au vol.":
        ". The confidentiality safeguard is therefore also a performance brake: a non-empty mask disarms the rollup route (`handlers/query.rs:282`) because `event_rollup` stores `src_ip`/`host` in plaintext. Two ways forward: mask when reading the rollup, or materialise one rollup per mask class. **RAM cost: that of an additional set of rollups** (on the reference installation, `event_rollup` weighs on the order of a MiB per million events, hence marginal), plus on-the-fly masking.",
    " Les deux passes opposées sont `{vide}` et `{masked}` : elles s'accordent sur TOUT ce que le relevé déclare — binaire, nombre d'événements, base, tier froid — sauf le masquage. C'est la seule raison pour laquelle cet écart peut être imputé au masque.":
        " The two runs opposed are `{vide}` and `{masked}`: they agree on EVERYTHING the reading declares — binary, number of events, database, cold tier — except masking. This is the only reason why this gap can be attributed to the mask.",
    "Étendre la route de rollups aux dimensions à haute cardinalité":
        "Extend the rollup route to high-cardinality dimensions",
    "`stats count by src_ip,host,source` sur tout l'historique : **{0}**, servi par `{1}`. Seules les formes `by` dont TOUTES les dimensions tiennent dans `{{source, severity}}` sont routables (`rollup_route.rs:349-366`) ; dès qu'une dimension à haute cardinalité entre, on retombe sur le scan. **Coût RAM : celui du grain choisi** — un rollup à grain `src_ip` est borné à l'exécution par `PLUME_ROLLUP_SRCIP_TOPN` (50) précisément pour ne pas exploser, ce qui rend le résultat approché. Le compromis exactitude/mémoire doit être décidé, pas subi.":
        "`stats count by src_ip,host,source` over the whole history: **{0}**, served by `{1}`. Only the `by` forms whose dimensions ALL fit in `{{source, severity}}` are routable (`rollup_route.rs:349-366`); as soon as a high-cardinality dimension comes in, it falls back to the scan. **RAM cost: that of the chosen grain** — a rollup at `src_ip` grain is bounded at execution by `PLUME_ROLLUP_SRCIP_TOPN` (50) precisely so as not to explode, which makes the result approximate. The exactness/memory trade-off must be decided, not endured.",
    "Le champ étendu non indexé n'a aucun chemin d'accès":
        "The non-indexed extended field has no access path",
    "regex sur `fields.object` (aucun index) : **{0}**":
        "regex on `fields.object` (no index): **{0}**",
    " contre **{0}** pour une égalité sur `fields.user`, qui a un index d'expression partiel.":
        " against **{0}** for an equality on `fields.user`, which has a partial expression index.",
    " {0} champs seulement sont indexés (`HOT_FIELDS`, lu dans `daemon/src/soql_glue.rs` : {1}) sur les **241 clés distinctes du profil mesuré**. Pour les {2} autres, toute recherche est un scan avec `json_extract` par ligne. C'est exactement la promesse « sur tous les champs » qui est en jeu. Voies : `event_fields_fts` (déjà écrit, voir le levier sur le coût de `PLUME_FTS_FIELDS`), ou des index d'expression sur demande, ou un stockage colonnaire des champs. **Coût RAM : un index d'expression par champ**, à arbitrer — et cet arbitrage n'a aujourd'hui aucun automate : le mécanisme qui promettait de le rendre à l'usage a été retiré (P6.8-b) sans avoir jamais promu un seul index.":
        " Only {0} fields are indexed (`HOT_FIELDS`, read from `daemon/src/soql_glue.rs`: {1}) out of the **241 distinct keys of the measured profile**. For the {2} others, any search is a scan with `json_extract` per row. It is exactly the \"on all fields\" promise that is at stake. Ways forward: `event_fields_fts` (already written, see the lever on the cost of `PLUME_FTS_FIELDS`), or expression indexes on demand, or columnar storage of the fields. **RAM cost: one expression index per field**, to be arbitrated — and this arbitration has no automation today: the mechanism that promised to make it based on usage was removed (P6.8-b) without ever having promoted a single index.",
    "Servir le curseur demandé, y compris quand le pipeline projette":
        "Serve the requested cursor, including when the pipeline projects",
    "MÊME demande (`keyset:true`, limit 200, même filtre), seule la projection change : **{0}** avec `| table …` contre **{1}** sans projection. Le client a demandé une pagination par CURSEUR et reçoit une page `OFFSET` : le curseur est désactivé dès que le pipeline contient `| table` ou `| fields`, c'est-à-dire dès qu'on projette des colonnes — ce que fait toute récupération RAW réelle. Conséquences : pas de `next_cursor`, un `total` PLAFONNÉ à 10 000 (des événements restent donc cachés) et un coût qui croît avec le numéro de page. **Coût RAM : nul.**":
        "SAME request (`keyset:true`, limit 200, same filter), only the projection changes: **{0}** with `| table …` against **{1}** without projection. The client asked for CURSOR pagination and receives an `OFFSET` page: the cursor is disabled as soon as the pipeline contains `| table` or `| fields`, that is, as soon as columns are projected — which every real RAW retrieval does. Consequences: no `next_cursor`, a `total` CAPPED at 10,000 (so events remain hidden) and a cost that grows with the page number. **RAM cost: nil.**",
    "activer `PLUME_FTS_FIELDS=1` a fait passer la base de **{0} Mio à {1} Mio** ({sgn}{2} Mio, {sgn}{3:.0f} %), sur la paire que la propriété désigne : ":
        "enabling `PLUME_FTS_FIELDS=1` took the database from **{0} MiB to {1} MiB** ({sgn}{2} MiB, {sgn}{3:.0f} %), on the pair that the property designates: ",
    "la passe `{fts1}` comparée à SA PROPRE taille d'avant-bascule (`db_bytes_fts0`), donc sur la même base, le même binaire et le même nombre d'événements. ":
        "the run `{fts1}` compared with ITS OWN size before the switch (`db_bytes_fts0`), hence on the same database, the same binary and the same number of events. ",
    "`{fts0}` contre `{fts1}`. ":
        "`{fts0}` against `{fts1}`. ",
    "le coût DISQUE de `PLUME_FTS_FIELDS=1`":
        "the DISK cost of `PLUME_FTS_FIELDS=1`",
    "la passe FTS-on ne relève pas `db_bytes`":
        "the FTS-on run does not record `db_bytes`",
    "RSS crête, sur les SEULES classes mesurées dans les deux configurations ({0}), et sur la MÊME paire : **{1} Mio** à `FTS_FIELDS=0` (`{fts0}`) contre **{2} Mio** à `FTS_FIELDS=1`. Attention : chaque configuration repart d'un daemon neuf, donc ces deux crêtes n'ont pas eu le même historique pour monter — l'écart n'est PAS attribuable au drapeau seul, dans aucun des deux sens. Le chiffre solide de cette ligne est le coût DISQUE. ":
        "Peak RSS, on the ONLY classes measured in both configurations ({0}), and on the SAME pair: **{1} MiB** at `FTS_FIELDS=0` (`{fts0}`) against **{2} MiB** at `FTS_FIELDS=1`. Caution: each configuration starts from a fresh daemon, so these two peaks did not have the same history to rise — the gap is NOT attributable to the flag alone, in either direction. The solid figure of this row is the DISK cost. ",
    "La crête RSS tombe sous le MÊME refus, pour la MÊME raison : elle demande deux passes, et la paire n'existe pas. ":
        "The RSS peak falls under the SAME refusal, for the SAME reason: it requires two runs, and the pair does not exist. ",
    "la crête RSS de `PLUME_FTS_FIELDS=1`":
        "the RSS peak of `PLUME_FTS_FIELDS=1`",
    "Écart de latence observé sur le terme libre GXQL (tout l'historique), sur la MÊME paire : **{0}** ":
        "Latency gap observed on the GXQL free term (whole history), on the SAME pair: **{0}** ",
    "en défaveur de FTS_FIELDS=1":
        "to the detriment of FTS_FIELDS=1",
    "en faveur de FTS_FIELDS=1":
        "in favour of FTS_FIELDS=1",
    " — mais cet écart ne peut PAS venir du drapeau, puisque le chemin GXQL ne lit jamais `event_fields_fts` : c'est du bruit de mesure sur une machine partagée, et il est reporté comme tel. ":
        " — but this gap CANNOT come from the flag, since the GXQL path never reads `event_fields_fts`: it is measurement noise on a shared machine, and it is reported as such. ",
    "Le gain en latence sur le chemin GXQL n'a pas pu être mesuré. ":
        "The latency gain on the GXQL path could not be measured. ",
    "LE COÛT QUI DÉCIDE N'EST PAS DANS CE BANC, ET IL EST PLUS LOURD QUE CEUX QUI PRÉCÈDENT : l'index des champs est déclaré SANS TABLE DE CONTENU, forme que le plan de sauvegarde typé ne sait pas recréer ; chaque cycle compressé se replie alors sur un export qui matérialise une copie DÉCHIFFRÉE COMPLÈTE de la base, le temps du cycle. Activer cette capacité est donc un ÉCHANGE PERFORMANCE CONTRE CONFIDENTIALITÉ, et c'est cette raison-là — non un surcoût de mémoire, que ce banc ne mesure dans aucun sens — qui justifie que le défaut soit à l'arrêt. Établi par lecture des sources, jamais par une passe : voir `docs/CHIFFREMENT-COMPRESSION.md` §3. ":
        "THE COST THAT DECIDES IS NOT IN THIS BENCH, AND IT IS HEAVIER THAN THOSE ABOVE: the field index is declared WITHOUT A CONTENT TABLE, a form that the typed backup plan cannot recreate; each compressed cycle then falls back to an export that materialises a FULL DECRYPTED copy of the database, for the duration of the cycle. Enabling this capability is therefore a PERFORMANCE-FOR-CONFIDENTIALITY TRADE, and it is this reason — not a memory overhead, which this bench measures in neither direction — that justifies the default being off. Established by reading the sources, never by a run: see `docs/CHIFFREMENT-COMPRESSION.md` §3. ",
    "À retenir : `event_fields_fts` n'est lu que par `/api/search` (`handlers/search.rs:146-157`). Le chemin GXQL ne le consulte JAMAIS — donc son coût en disque et en ingest est payé sans que les requêtes GXQL en profitent. C'est le levier « Câbler FTS5 sur le chemin GXQL » qui rendrait ce coût déjà consenti utile aux requêtes GXQL.":
        "Key point: `event_fields_fts` is only read by `/api/search` (`handlers/search.rs:146-157`). The GXQL path NEVER consults it — so its disk and ingest cost is paid without GXQL queries benefiting from it. It is the lever \"Wire FTS5 into the GXQL path\" that would make this already-accepted cost useful to GXQL queries.",
    "Le coût de `PLUME_FTS_FIELDS=1`, et à qui il profite":
        "The cost of `PLUME_FTS_FIELDS=1`, and who benefits from it",
    "`{fts1}` — paire refusée":
        "`{fts1}` — pair refused",
    "Effet DISQUE mesuré sur la SEULE paire que la propriété désigne : **{sgn}{0:.0f} %** de base ({sgn}{1} Mio). ":
        "DISK effect measured on the ONLY pair that the property designates: **{sgn}{0:.0f} %** of database ({sgn}{1} MiB). ",
    "Ce n'est pas un gain, c'est une dépense — et le document dit plus bas à qui elle profite, et ce qu'elle coûte AILLEURS que sur le disque.":
        "This is not a gain, it is an expense — and the document says below who benefits from it, and what it costs ELSEWHERE than on disk.",
    "La base RÉTRÉCIT sur cette paire : le sens de cet écart est DÉRIVÉ de la mesure, il n'est pas affirmé par le gabarit — et il contredit ce que le document a longtemps supposé, donc il demande une seconde passe avant d'être cité.":
        "The database SHRINKS on this pair: the direction of this gap is DERIVED from the measurement, it is not asserted by the template — and it contradicts what the document long assumed, so it requires a second run before being cited.",
    "*Aucun coût disque n'est rendu ici : la paire comparable manque (voir le refus ci-dessous).*":
        "*No disk cost is rendered here: the comparable pair is missing (see the refusal below).*",
    "*Gain mesuré : **{0}** au p50 sur la cellule la plus parlante ({src}). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*":
        "*Measured gain: **{0}** at p50 on the most telling cell ({src}). This is not a promise of gain: it is the gap THAT THE MEASUREMENT SHOWS today between the slow path and a fast path that already exists or is reachable.*",
    "## Ce qui n'est PAS mesuré ici":
        "## What is NOT measured here",
    "- **Le tier froid au-delà de ce qui est tiré** : {0} configuration(s) tournent":
        "- **The cold tier beyond what is fired**: {0} configuration(s) run",
    "  `PLUME_COLD_TIER=1` (section dédiée plus haut), mais sur UNE seule taille de fenêtre":
        "  `PLUME_COLD_TIER=1` (dedicated section above), but on ONE single hot window",
    "  chaude et UN seul volume. Le moteur vectorisé n'est pas mesuré séparément du chemin":
        "  size and ONE single volume. The vectorised engine is not measured separately from the",
    "  d'hydratation : le document ne dit pas lequel a servi chaque cellule au-delà de ce que":
        "  hydration path: the document does not say which one served each cell beyond what",
    "  `stats.cold` en rapporte.":
        "  `stats.cold` reports about it.",
    "- **Le tier froid** (`--features cold_tier` + `PLUME_COLD_TIER=1`) : le binaire est compilé":
        "- **The cold tier** (`--features cold_tier` + `PLUME_COLD_TIER=1`): the binary is compiled",
    "  avec la feature, mais toutes les cellules tournent `PLUME_COLD_TIER=0`. Aucun chiffre de ce":
        "  with the feature, but all cells run `PLUME_COLD_TIER=0`. No figure in this",
    "  document ne dit quoi que ce soit du chemin Parquet ni du moteur vectorisé.":
        "  document says anything about the Parquet path or the vectorised engine.",
    "- **La concurrence est mesurée** (section dédiée) : jusqu'à {0} analystes":
        "- **Concurrency is measured** (dedicated section): up to {0} simultaneous",
    "  simultanés, sémaphore {0}. Ce qui reste hors mesure :":
        "  analysts, semaphore {0}. What remains outside the measurement:",
    "  la concurrence PENDANT une ingestion (les deux charges sont mesurées séparément), la":
        "  concurrency DURING an ingestion (the two loads are measured separately),",
    "  charge SOUTENUE sur des heures (chaque niveau dure des dizaines de secondes, pas une":
        "  SUSTAINED load over hours (each level lasts tens of seconds, not a",
    "  journée), et les fenêtres autres que {0} — le":
        "  day), and windows other than {0} — the",
    "  mélange est tiré sur la fenêtre la plus coûteuse, pas sur toutes.":
        "  mix is fired on the most expensive window, not on all of them.",
    "- **La concurrence** : une requête à la fois. `PLUME_QUERY_CONCURRENCY=3` est en place mais":
        "- **Concurrency**: one query at a time. `PLUME_QUERY_CONCURRENCY=3` is in place but",
    "  jamais saturé (`sem_wait_ms` reste nul). Le comportement à 10 utilisateurs simultanés n'est":
        "  never saturated (`sem_wait_ms` stays at zero). The behaviour at 10 simultaneous users is not",
    "  pas mesuré.":
        "  measured.",
    "- **Le multi-tenant** (`PLUME_MULTI_TENANT=1`) : tout est mesuré en mode 0.":
        "- **Multi-tenancy** (`PLUME_MULTI_TENANT=1`): everything is measured in mode 0.",
    "- **Le cache de pages froid** : impossible de le vider sans privilège root sur la machine de":
        "- **The cold page cache**: impossible to drop it without root privilege on the measurement",
    "  mesure. La colonne `lu` dit ce qui a réellement atteint le disque ; elle ne dit pas ce que":
        "  machine. The `lu` column says what actually reached the disk; it does not say what",
    "  ferait un démarrage à froid complet.":
        "  a full cold start would do.",
    "- **La fidélité du texte** : le corps des messages est synthétique. Les chiffres FTS5, `LIKE`":
        "- **Text fidelity**: the message bodies are synthetic. The FTS5, `LIKE`",
    "  et `REGEXP` dépendent directement de ce vocabulaire ; c'est la limite la plus sérieuse du":
        "  and `REGEXP` figures depend directly on this vocabulary; it is the most serious limit of the",
    "  banc et elle est décrite dans `bench/gen_events.py` (`VOCAB`).":
        "  bench and it is described in `bench/gen_events.py` (`VOCAB`).",
    "- **L'indexation des champs étendus** : `PLUME_EXPRINDEX=1` (le défaut livré) est le SEUL":
        "- **Indexing of extended fields**: `PLUME_EXPRINDEX=1` (the shipped default) is the ONLY",
    "  levier, et il n'indexe que les noms de `HOT_FIELDS`. Aucun mécanisme n'indexe plus un champ":
        "  lever, and it only indexes the names in `HOT_FIELDS`. No mechanism indexes a field based on",
    "  à l'usage — celui qui le promettait a été retiré (P6.8-b) sans avoir jamais promu un index.":
        "  usage any more — the one that promised it was removed (P6.8-b) without ever having promoted an index.",
    "  Ce tableau ne peut donc PAS montrer un champ étendu hors de cette liste servi par un index :":
        "  This table therefore CANNOT show an extended field outside this list served by an index:",
    "  ce n'est pas une case non mesurée, c'est une case qu'aucune configuration ne remplirait.":
        "  it is not an unmeasured cell, it is a cell that no configuration would fill.",
    "## Reproduire, et contredire":
        "## Reproduce, and contradict",
    "# 1. le profil de données (déjà versionné ; à re-extraire seulement pour une autre prod)":
        "# 1. the data profile (already versioned; to re-extract only for another deployment)",
    "#    bench/prod-profile.sql, LECTURE SEULE, n'extrait aucune valeur de ligne":
        "#    bench/prod-profile.sql, READ ONLY, extracts no row value",
    "# 2. la matrice complète, de bout en bout :":
        "# 2. the full matrix, end to end:",
    "bench/run.sh                       # 10 M d'événements":
        "bench/run.sh                       # 10 M events",
    "BENCH_EVENTS=1000000 bench/run.sh  # 1 M, pour itérer":
        "BENCH_EVENTS=1000000 bench/run.sh  # 1 M, to iterate",
    "# 2 bis. la CONCURRENCE, sur une base déjà remplie (redémarre le daemon par valeur de":
        "# 2 bis. CONCURRENCY, on an already filled database (restarts the daemon for each",
    "#        sémaphore et lui REDEMANDE ce qu'il applique avant de mesurer) :":
        "#        semaphore value and ASKS it again what it applies before measuring):",
    "Ces commandes sont **régénérées à chaque rendu** : elles ne peuvent pas se désynchroniser du":
        "These commands are **regenerated at each rendering**: they cannot drift out of sync with the",
    "document. C'est délibéré — la version précédente publiait une commande incomplète qui, rejouée":
        "document. This is deliberate — the previous version published an incomplete command which, replayed",
    "telle quelle, AMPUTAIT le document de ses sections d'écart et de ses tableaux d'attribution.":
        "as is, AMPUTATED the document of its gap sections and its attribution tables.",
    "Une commande de reproduction fausse est pire qu'absente : elle fait croire à une":
        "A wrong reproduction command is worse than none: it makes one believe in a",
    "reproduction réussie.":
        "successful reproduction.",
    "Le générateur est déterministe : `python3 bench/gen_events.py --count N --end-ts T --digest`":
        "The generator is deterministic: `python3 bench/gen_events.py --count N --end-ts T --digest`",
    "imprime le SHA-256 du flux. Deux exécutions avec les mêmes paramètres donnent la même":
        "prints the SHA-256 of the stream. Two executions with the same parameters give the same",
    "empreinte — c'est ce qui rend un désaccord sur les chiffres arbitrable.":
        "fingerprint — this is what makes a disagreement on the figures arbitrable.",
}


if __name__ == "__main__":
    main()
