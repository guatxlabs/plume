#!/usr/bin/env python3
"""bench/probe_hot_fields.py — LE CHAMP QU'UN TIERS INTERROGE EST-IL INDEXÉ ?

LE TROU QU'IL BOUCHE
  Le daemon crée des index d'expression sur les champs étendus (`PLUME_EXPRINDEX`, défaut **1**),
  mais UNIQUEMENT sur une liste ÉCRITE EN DUR de dix noms (`soql_glue.rs`, `HOT_FIELDS`) :
  `action, user, owner, kind, ns, role, scope, verb, resource, operation`.
  L'indexation ADAPTATIVE pilotée par l'usage existe (`maintenance.rs`, `autoindex_tick`) mais
  `PLUME_AUTOINDEX` vaut **0** par défaut (`server.rs`) : elle est INACTIVE hors configuration.

  Conséquence : hors configuration, un exploitant n'a d'index que sur ces dix noms. Celui dont le
  champ discriminant s'appelle `process_name`, `dst_port` ou `rule_name` tombe en SCAN — et rien ne
  le lui dit. C'est la même forme que le constat sur les noms de sources : notre profil coïncide
  avec une table en dur, donc notre banc mesure le MEILLEUR CAS.

  Attention au raisonnement qui paraît suffisant et ne l'est pas : constater que l'auto-indexation
  EXISTE ne dit rien de ce qu'obtient un tiers. C'est le DÉFAUT qui tranche, pas la présence du
  mécanisme. La sonde relève donc le réglage EFFECTIF du daemon interrogé, elle ne le suppose pas.

L'EXPÉRIENCE, ET POURQUOI ELLE N'A PAS BESOIN D'UN SECOND JEU
  Comparer deux jeux introduirait un remplissage différent. Ici tout se joue DANS LE MÊME JEU : on
  compare deux clés étendues APPARIÉES — même type, même cardinalité, même taux de présence — dont
  l'une seulement est dans `HOT_FIELDS`, avec le MÊME opérateur (égalité). La seule différence
  structurelle entre les deux requêtes est donc l'existence d'un index.

  LA PAIRE EST DÉRIVÉE DU PROFIL, PAS CHOISIE : le script prend la paire (hot, non-hot) qui minimise
  l'écart de cardinalité (en log) et de taux de présence, puis, à égalité, celle dont le taux de
  présence est le PLUS ÉLEVÉ — une paire présente sur 0,02 % des lignes ne mesurerait rien. La paire
  retenue et sa qualité d'appariement sont publiées avec la mesure : un lecteur peut la contester.
"""
import argparse
import json
import math
import statistics
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from measure import Client  # noqa: E402

HOT_FIELDS = ["action", "user", "owner", "kind", "ns", "role", "scope",
              "verb", "resource", "operation"]
PROMOTED = {"src_ip", "dst_ip", "url", "rhost"}


def derive_pair(profile_path):
    p = json.load(open(profile_path, encoding="utf-8"))
    tot = sum(s["n"] for s in p["sources"]["list"]) or 1
    agg = {}
    for s in p["sources"]["list"]:
        for f in s.get("fields") or []:
            k = f["key"]
            if k in PROMOTED or k == "cim":
                continue
            a = agg.setdefault(k, {"n": 0, "card": 1, "type": f["type"]})
            a["n"] += f["n"]
            a["card"] = max(a["card"], f.get("card") or 1)
    rate = lambda k: agg[k]["n"] / tot
    cands = []
    for h in (k for k in agg if k in HOT_FIELDS):
        for c in (k for k in agg if k not in HOT_FIELDS):
            if agg[h]["type"] != agg[c]["type"]:
                continue
            d = (math.log10(agg[h]["card"] / agg[c]["card"])) ** 2 + (4 * (rate(h) - rate(c))) ** 2
            # tri : appariement d'abord, PUIS signal (présence la plus forte). Sans le second
            # critère, une paire parfaitement appariée mais présente sur 0,02 % des lignes
            # gagnerait — et elle ne mesurerait que le coût fixe d'une requête.
            cands.append((round(d, 6), -min(rate(h), rate(c)), h, c))
    if not cands:
        sys.exit("aucune paire (hot, non-hot) appariable dans ce profil")
    cands.sort()
    d, negr, h, c = cands[0]
    return dict(hot_key=h, cold_key=c, distance=d,
                hot_card=agg[h]["card"], cold_card=agg[c]["card"],
                hot_rate=round(rate(h), 5), cold_rate=round(rate(c), 5),
                type=agg[h]["type"], candidates_considered=len(cands))


def run(cli, soql, frm, to, reps):
    out = []
    for _ in range(reps):
        t0 = time.monotonic()
        st, body = cli.call("/api/query", {"soql": soql, "from": frm, "to": to,
                                           "interactive": True})
        wall = (time.monotonic() - t0) * 1000.0
        s = (body or {}).get("stats") or {}
        out.append(dict(status=st, wall_ms=round(wall, 3), sql_ms=s.get("elapsed_ms"),
                        rows=s.get("rows"), served_from=s.get("served_from"),
                        compiled_sql=(body or {}).get("compiled_sql"),
                        error=(body or {}).get("_error")))
    return out


def top_value(cli, key, frm, to):
    """LA VALEUR EST LUE DANS LE JEU, PAS FABRIQUÉE. Le générateur n'encode pas les valeurs de la
    même façon selon la longueur moyenne de la clé (`gen_events.py::value_of` : énumération
    `000`..`004` en dessous de 5 caractères, tige hexadécimale au-dessus). Une valeur écrite à la
    main dans cette sonde marcherait donc pour une clé et pas pour l'autre — et les DEUX côtés
    rendraient 0 ligne, ce qui donnerait un rapport de deux planchers, c'est-à-dire un chiffre
    parfaitement stable et parfaitement faux. On demande donc au jeu sa valeur la plus fréquente."""
    st, body = cli.call("/api/query", {
        "soql": f"search | stats count by {key} | sort -count | head 3",
        "from": frm, "to": to, "interactive": True})
    if st != 200:
        return None
    for row in ((body or {}).get("rows") or []):
        if row and row[0] not in (None, "", "-"):
            return str(row[0])
    return None


def side(cli, key, val, frm, to, reps):
    soql = f"search {key}={val} | stats count"
    rs = run(cli, soql, frm, to, reps)
    ok = [r for r in rs if r["status"] == 200 and not r["error"]]
    w = [r["wall_ms"] for r in ok]
    return dict(key=key, value=val, value_len=len(val or ""), query=soql, samples_ms=w,
                median_ms=round(statistics.median(w), 3) if w else None,
                sql_samples_ms=[r["sql_ms"] for r in ok],
                rows=(ok[0]["rows"] if ok else None),
                compiled_sql=(ok[0]["compiled_sql"] if ok else None),
                statuses=sorted({r["status"] for r in rs}),
                errors=sorted({r["error"] for r in rs if r["error"]}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--host-header", default="localhost")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--admin-user", default="")
    ap.add_argument("--admin-password", default="")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--end-ts", type=int, required=True)
    ap.add_argument("--span-days", type=int, default=28)
    ap.add_argument("--reps", type=int, default=7)
    ap.add_argument("--config-id", required=True)
    ap.add_argument("--phase-label", default="défaut livré")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()

    pair = derive_pair(a.profile)
    cli = Client(a.base, a.user, a.password, a.host_header)
    frm = a.end_ts - a.span_days * 86400

    # LE RÉGLAGE EFFECTIF, DEMANDÉ AU DAEMON — jamais supposé depuis le code ni depuis l'étiquette
    # de la passe. C'est précisément le piège que cette sonde doit éviter : « le mécanisme existe »
    # n'est pas « le mécanisme est actif ».
    applied = {}
    if a.admin_user:
        acli = Client(a.base, a.admin_user, a.admin_password, a.host_header)
        st, body = acli.call("/api/system/diag")
        if st == 200 and isinstance(body, dict):
            blob = json.dumps(body)
            for k in ("PLUME_AUTOINDEX", "PLUME_EXPRINDEX", "PLUME_AUTOINDEX_MIN_HITS",
                      "PLUME_AUTOINDEX_MIN_SLOW", "PLUME_AUTOINDEX_INTERVAL"):
                i = blob.find(k)
                applied[k] = blob[i:i + 80] if i >= 0 else None

    hv = top_value(cli, pair["hot_key"], frm, a.end_ts)
    cv = top_value(cli, pair["cold_key"], frm, a.end_ts)
    if not hv or not cv:
        sys.exit(f"valeur introuvable pour {pair['hot_key']!r}={hv!r} ou {pair['cold_key']!r}={cv!r} "
                 "— la sonde REFUSE de mesurer : sans valeur présente dans le jeu, les deux côtés "
                 "rendraient 0 ligne et leur rapport serait un rapport de planchers.")
    hot = side(cli, pair["hot_key"], hv, frm, a.end_ts, a.reps)
    cold = side(cli, pair["cold_key"], cv, frm, a.end_ts, a.reps)
    # LA GARDE QUI EMPÊCHE DE PUBLIER UN CHIFFRE VIDE. Un rapport calculé sur deux résultats à zéro
    # ligne est parfaitement reproductible et parfaitement faux : c'est le coût fixe d'une requête
    # divisé par lui-même. On refuse, en NOMMANT le côté fautif.
    if not hot["rows"] or not cold["rows"]:
        sys.exit(f"0 ligne d'un côté au moins ({hot['key']}={hv!r} -> {hot['rows']} ; "
                 f"{cold['key']}={cv!r} -> {cold['rows']}) — la sonde REFUSE de publier un rapport "
                 "qui ne comparerait que des planchers.")

    rec = dict(phase="hot_fields_probe", config_id=a.config_id, phase_label=a.phase_label,
               profile=a.profile.rsplit("/", 1)[-1], pair=pair,
               applied_settings=applied, hot=hot, cold=cold,
               ratio_cold_over_hot=(round(cold["median_ms"] / hot["median_ms"], 3)
                                    if hot["median_ms"] and cold["median_ms"] else None),
               loadavg=open("/proc/loadavg").read().split()[:3],
               measured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    with open(a.out, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"{a.config_id:22} [{a.phase_label}] paire DÉRIVÉE {pair['hot_key']}(HOT) vs "
          f"{pair['cold_key']} — card {pair['hot_card']}/{pair['cold_card']}, "
          f"présence {pair['hot_rate']:.4f}/{pair['cold_rate']:.4f}")
    print(f"    indexée  {hot['key']:12} médiane={hot['median_ms']}ms  lignes={hot['rows']}")
    print(f"    NON idx  {cold['key']:12} médiane={cold['median_ms']}ms  lignes={cold['rows']}")
    print(f"    RAPPORT non-indexé / indexé = x{rec['ratio_cold_over_hot']}")


if __name__ == "__main__":
    main()
