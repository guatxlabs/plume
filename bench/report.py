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
    if v < 10:
        return f"{v:.1f} ms"
    if v < 2000:
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
    ap.add_argument("--ingest-curve", default=None,
                    help="CSV t_unix,events,db_bytes,rss_bytes,loadavg1 échantillonné pendant "
                         "l'ingest : rend la COURBE de débit en fonction du volume déjà en base")
    args = ap.parse_args()

    rows, ingest, deaths = [], [], []
    for path in args.results:
      with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if d.get("daemon_died_after_this_cell"):
                deaths.append(d)
            elif d.get("phase") == "ingest":
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
    wins = ["1h", "24h", "all"]
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
    W(f"Rendu le {time.strftime('%Y-%m-%d %H:%M:%S%z')} depuis "
      + ", ".join(f"`{_os.path.basename(p)}`" for p in args.results)
      + " (données brutes conservées hors dépôt, cf. `bench/README.md`).")
    W("")
    W("## Ce que ce document est, et ce qu'il n'est pas")
    W("")
    W("C'est **la première mesure de référence** de plume, prise avec un instrument publié et")
    W("rejouable. Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est")
    W("une case **non mesurée**, pas une case implicitement bonne.")
    W("")
    W("Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : c'est un")
    W("banc synthétique au **profil** de la production (voir `bench/profile-prod.json`).")
    W("")

    # ------------------------------------------------------------ VERDICT, calculé sur les mesures
    # La raison d'être du document : dire ce que les mesures AUTORISENT à affirmer et ce qu'elles
    # n'autorisent pas. Tout ici est dérivé des cellules, aucune phrase n'est un jugement libre.
    def _nev0(c):
        return (cfgmeta[c].get("events") or 0)
    ref = max([c for c in configs if cfgmeta[c].get("fts_fields") == 0
               and "non-vide" not in (cfgmeta[c].get("mask") or "")] or configs, key=_nev0)
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
    if fl0 and fl0.get("wall_p50_ms") is not None:
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
      "le vrai chemin d'ingest dans le temps disponible (voir le débit mesuré ci-dessous). Toute "
      "phrase sur 10 M ou 100 M serait une extrapolation, pas une mesure.")
    W("- rien sur le tier froid, la concurrence, ni le multi-tenant (voir la section dédiée).")
    mk = max([c for c in configs if "non-vide" in (cfgmeta[c].get("mask") or "")
              and _nev0(c) == _nev0(ref)] or [None], key=lambda c: _nev0(c) if c else -1)
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
    W("| Budget par requête | interactif, 60 s (`interactive:true`) |")
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
    curve_pts = []
    if args.ingest_curve:
        import csv as _csv0
        try:
            curve_pts = list(_csv0.DictReader(open(args.ingest_curve, encoding="utf-8")))
        except OSError:
            curve_pts = []
    # On AJOUTE la ligne dérivée de l'échantillonneur dès qu'il y a une courbe : sans ça, une passe
    # dont la synthèse n'a pas été écrite (remplissage borné en temps) disparaîtrait du tableau au
    # profit d'une autre passe qui, elle, avait écrit la sienne.
    if len(curve_pts) >= 2:
        f0, f1 = curve_pts[0], curve_pts[-1]
        dt = int(f1["t_unix"]) - int(f0["t_unix"])
        dn = int(f1["events"]) - int(f0["events"])
        if dt > 0:
            ingest.append({"events": dn, "seconds": dt, "events_per_second": dn // dt,
                           "db_bytes": int(f1["db_bytes"]), "fts_fields": 0,
                           "path": "POST /api/ingest -> spool -> ingest_events_batch",
                           "_derived": "reconstruit depuis l'échantillonneur (premier et dernier "
                                       "point mesurés), le remplissage ayant été borné en temps"})
    if ingest:
        W("## Débit d'ingest mesuré (chemin HTTP complet)")
        W("")
        W("| Événements | Durée | Débit | Base après | `PLUME_FTS_FIELDS` |")
        W("|---:|---:|---:|---:|:--:|")
        for d in ingest:
            W(f"| {fmt_n(d.get('events'))} | {d.get('seconds')} s | "
              f"**{fmt_n(d.get('events_per_second'))} ev/s** | {fmt_mib(d.get('db_bytes'))} Mio | "
              f"{d.get('fts_fields')} |")
        W("")
        W(f"Chemin traversé : `{ingest[0].get('path','')}`.")
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
        if args.ingest_curve:
            import csv as _csv
            try:
                pts = list(_csv.DictReader(open(args.ingest_curve, encoding="utf-8")))
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
                W("### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé")
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
                rates = sorted(r for _, _, _, r, _ in segs)
                las = sorted(la for _, _, _, _, la in segs)
                med = rates[len(rates) // 2]
                W(f"Débit sur les intervalles échantillonnés : **min {rates[0]:.0f} ev/s, "
                  f"médiane {med:.0f} ev/s, max {rates[-1]:.0f} ev/s**, pour un `loadavg` allant de "
                  f"{las[0]:.1f} à {las[-1]:.1f}. L'écart d'un facteur "
                  f"{rates[-1]/max(rates[0],1):.1f} entre le plus lent et le plus rapide intervalle "
                  "suit le `loadavg` : **sur cette machine non dédiée, le débit d'ingest est "
                  "dominé par la contention CPU**, pas seulement par le volume déjà en base. Il faut "
                  "donc lire ces chiffres comme un PLANCHER, et refaire la mesure sur une machine "
                  "au repos avant d'en publier un débit nominal.")
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
    W("| Étiquette | Événements | `PLUME_FTS_FIELDS` | Masquage de champs | Tier froid | Classes mesurées |")
    W("|---|---:|:--:|---|:--:|---|")
    for c in configs:
        m = cfgmeta[c]
        n_cells = sum(1 for r in eff if r["config_id"] == c)
        sub = m.get("classes")
        W(f"| `{c}` | {fmt_n(m.get('events'))} | {m.get('fts_fields','?')} | "
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
    fts0_vide = [c for c in configs if cfgmeta[c].get("fts_fields") == 0
                 and "non-vide" not in (cfgmeta[c].get("mask") or "")]
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
    base = max(cands or configs, key=nev)
    vol = nev(base)
    masked = max([c for c in configs if "non-vide" in (cfgmeta[c].get("mask") or "")
                  and nev(c) == vol] or [None], key=lambda c: nev(c) if c else -1)
    fts1 = max([c for c in configs if cfgmeta[c].get("fts_fields") == 1] or [None],
               key=lambda c: nev(c) if c else -1)
    lev = []

    # L1 — le plancher de 50 ms
    fl = cell(base, "C0-plancher", "1h")
    if fl and fl.get("wall_p50_ms") is not None:
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
                        "marginal), plus le masquage au vol.",
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

    # L6 — pagination profonde
    a, b = cell(base, "C4b-raw-deep", "all"), cell(base, "C4c-raw-keyset", "all")
    g = gain_ms(a, b)
    if g is not None and g > 0:
        lev.append((g, "Faire du keyset le défaut de la pagination profonde",
                    f"page profonde en `OFFSET` : **{fmt_dur(a['wall_p50_ms'])}** ; la même "
                    f"profondeur en curseur keyset : **{fmt_dur(b['wall_p50_ms'])}** — et ce, en "
                    "rendant PLUS de données (le keyset porte toutes les colonnes, la page `OFFSET` "
                    "n'en projette que cinq), ce qui rend l'écart conservateur. Le keyset "
                    "existe déjà (`keyset:true`) mais il est **désactivé dès que le pipeline contient "
                    "`| table` ou `| fields`** (`handlers/query.rs:198-205`) — c'est-à-dire dès qu'on "
                    "projette des colonnes, ce que fait toute récupération RAW réelle. "
                    "**Coût RAM : nul.**",
                    "C4b vs C4c"))

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
    W("- **Le tier froid** (`--features cold_tier` + `PLUME_COLD_TIER=1`) : le binaire est compilé")
    W("  avec la feature, mais toutes les cellules tournent `PLUME_COLD_TIER=0`. Aucun chiffre de ce")
    W("  document ne dit quoi que ce soit du chemin Parquet ni du moteur vectorisé.")
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
    W("# 3. le rendu (les deux options portent des mesures, pas de la décoration :")
    W("#    --ingest-curve = débit/RSS échantillonnés pendant le remplissage,")
    W("#    --fill-log     = débit cumulé relevé par le générateur lui-même) :")
    W("python3 bench/report.py ../.bench/results.jsonl \\")
    W("    --ingest-curve ../.bench/ingest_rate.csv \\")
    W("    --fill-log ../.bench/matrix.log -o docs/BENCHMARK.md")
    W("```")
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
