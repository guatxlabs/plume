#!/usr/bin/env python3
"""bench/probe_route_b.py — LE NOM DE LA SOURCE DÉCIDE-T-IL DE LA ROUTE ?

CE QUE CETTE SONDE MESURE, ET POURQUOI ELLE EXISTE SÉPARÉMENT DE LA MATRICE
  La matrice de `bench/measure.py` ne tire AUCUNE requête de la forme `search source=X | stats
  count by <dim>`. C'est un angle mort, et il porte sur la route la plus dépendante de la donnée de
  tout le produit : la ROUTE B (`daemon/src/rollup_route.rs`), servie depuis `event_dim_rollup`.

  Cette route n'est prise que si le couple (nom de source, dimension) figure dans
  `DIM_ROLLUP_SPECS` (`daemon/src/rollups.rs`) — une table ÉCRITE EN DUR dans le daemon :
  `web`->status/vhost/path, `auditd`->exe/comm/auid/key/action, `kube-audit`->verb/user/resource,
  `ufw`->dport/proto, `k8s-log`->ns/pod/level…

  Or le profil du banc porte les noms de sources de NOTRE production, qui sont exactement les clés
  de cette table. Autrement dit : notre banc mesure le cas où la couverture est MAXIMALE, et il
  n'existe aucune cellule publiée qui dise ce qu'obtient un exploitant dont les sources s'appellent
  autrement. C'est précisément la question « est-ce que nos chiffres tiennent chez un tiers ».

L'EXPÉRIENCE
  Deux jeux IDENTIQUES à un détail près : le nom des sources (`bench/make_axis_profile.py
  --rename-sources`). Même volume, même graine, mêmes cardinalités, mêmes sévérités, mêmes
  longueurs — vérifié par le profil lui-même, qui republie ses statistiques avant/après. La MÊME
  requête, avec le nom qui va avec le jeu. Si la latence bouge, elle ne peut bouger QUE pour cette
  raison.

CE QUI EST RELEVÉ, ET POURQUOI CE N'EST PAS QUE LA LATENCE
  `stats.served_from` dit par quelle route le daemon a répondu, et `stats.approx` dit si la réponse
  est un agrégat de rollup. Une différence de latence sans différence de route serait du bruit ;
  une différence de ROUTE est une preuve directe. La sonde publie les deux, et c'est la route qui
  tranche.
"""
import argparse
import json
import statistics
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from measure import Client  # noqa: E402  — même client HTTP que la matrice


def run(cli, soql, frm, to, reps):
    out = []
    for _ in range(reps):
        t0 = time.monotonic()
        st, body = cli.call("/api/query", {"soql": soql, "from": frm, "to": to,
                                           "interactive": True})
        wall = (time.monotonic() - t0) * 1000.0
        s = (body or {}).get("stats") or {}
        out.append(dict(status=st, wall_ms=round(wall, 3), server_ms=s.get("server_ms"),
                        sql_ms=s.get("elapsed_ms"), served_from=s.get("served_from"),
                        approx=s.get("approx"), truncated=s.get("truncated"),
                        rows=s.get("rows"), error=(body or {}).get("_error")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--host-header", default="localhost")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--source", required=True, help="nom de la source TEL QU'IL EST DANS CE JEU")
    ap.add_argument("--dim", default="exe", help="dimension du group-by (couple (source,dim))")
    ap.add_argument("--end-ts", type=int, required=True)
    ap.add_argument("--span-days", type=int, default=28)
    ap.add_argument("--reps", type=int, default=7)
    ap.add_argument("--config-id", required=True)
    ap.add_argument("--profile", default="")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()

    cli = Client(a.base, a.user, a.password, a.host_header)
    frm = a.end_ts - a.span_days * 86400
    soql = f"search source={a.source} | stats count by {a.dim}"
    # Le TÉMOIN de la même passe : la même forme SANS filtre de source, qui n'est jamais routable en
    # route B (elle exige un `source=` — rollup_route.rs). Il borne ce que la machine fait ce
    # jour-là, pour qu'un écart entre les deux jeux ne soit pas confondu avec une machine plus lente.
    soql_ctl = f"search | stats count by {a.dim}"

    runs = run(cli, soql, frm, a.end_ts, a.reps)
    ctl = run(cli, soql_ctl, frm, a.end_ts, a.reps)
    ok = [r for r in runs if r["status"] == 200 and not r["error"]]
    okc = [r for r in ctl if r["status"] == 200 and not r["error"]]
    rec = dict(
        phase="route_b_probe", config_id=a.config_id, profile=a.profile,
        source=a.source, dim=a.dim, query=soql, control_query=soql_ctl,
        end_ts=a.end_ts, span_days=a.span_days, reps=a.reps,
        wall_samples_ms=[r["wall_ms"] for r in ok],
        wall_median_ms=round(statistics.median([r["wall_ms"] for r in ok]), 3) if ok else None,
        sql_samples_ms=[r["sql_ms"] for r in ok],
        served_from=sorted({str(r["served_from"]) for r in ok}),
        approx=sorted({str(r["approx"]) for r in ok}),
        rows=(ok[0]["rows"] if ok else None),
        statuses=sorted({r["status"] for r in runs}),
        errors=sorted({r["error"] for r in runs if r["error"]}),
        control_wall_median_ms=(round(statistics.median([r["wall_ms"] for r in okc]), 3)
                                if okc else None),
        control_served_from=sorted({str(r["served_from"]) for r in okc}),
        loadavg=open("/proc/loadavg").read().split()[:3],
        measured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    )
    with open(a.out, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"{a.config_id:26} source={a.source:18} dim={a.dim:6} "
          f"median={rec['wall_median_ms']}ms route={rec['served_from']} approx={rec['approx']} "
          f"n={rec['rows']} | témoin(sans source=)={rec['control_wall_median_ms']}ms "
          f"{rec['control_served_from']}")


if __name__ == "__main__":
    main()
