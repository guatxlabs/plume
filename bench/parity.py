#!/usr/bin/env python3
"""bench/parity.py — LA RÉPONSE EST-ELLE LA MÊME ? Compare les VALEURS rendues avec et sans tier froid.

POURQUOI CE FICHIER EXISTE
  `measure.py` mesure des LATENCES. Il enregistre `rows` (combien de lignes sont revenues) et le
  drapeau `truncated`, mais JAMAIS les valeurs. Or « le froid est 3x plus rapide » ne veut rien dire
  si le froid a répondu 289 là où le chaud répondait 58 747 : une latence n'est comparable que si la
  réponse l'est. La passe du 31/07 a dû produire ses lignes `cold_parity` À LA MAIN — donc sans
  possibilité de les rejouer. Ce harnais les produit.

CE QU'IL COMPARE, ET COMMENT IL LE DÉRIVE
  Le jeu de contrôles n'est PAS écrit ici : c'est le PRODUIT CARTÉSIEN des classes de requêtes de
  `measure.py` (`query_classes`) par ses fenêtres DÉRIVÉES (`windows`) — exactement la matrice
  publiée. Ajouter une classe à `measure.py` ajoute donc ses contrôles de parité, sans toucher ce
  fichier. Les classes `kind="search"` sont incluses : /api/search est un chemin de lecture comme un
  autre, et son silence au-delà de la fenêtre chaude est précisément ce qu'il faut chiffrer.

CE QU'IL DÉCLARE
  `same` (les deux côtés rendent la MÊME réponse), `differs` (ils divergent SANS le dire — le cas
  GRAVE : un nombre faux, lisible, copiable), `declared` (ils divergent et le côté froid le DIT :
  drapeau `truncated` ou note de couverture), `refused` (un côté REFUSE explicitement : un 4xx
  nommé est un RÉSULTAT, et c'est la bonne réponse quand l'alternative est un nombre faux). Une
  requête en erreur des DEUX côtés est `same` : les deux chemins se comportent pareil.

  CE QUE `declared` NE DIT PAS : que la réponse est juste. Un AGRÉGAT tronqué reste un nombre
  faux, déclaré ou non — le drapeau ne le rachète pas, il prévient. Les catégories sont donc
  comptées séparément et ne s'additionnent JAMAIS en un « tout va bien ».
"""
import argparse
import hashlib
import json
import sys
import time

from measure import Client, query_classes, windows


def digest_rows(rows):
    """Empreinte STABLE d'un jeu de lignes, insensible à l'ORDRE (un `GROUP BY` SQL est un sac non
    ordonné ; comparer l'ordre ferait échouer des réponses identiques). Les lignes elles-mêmes sont
    comparées à l'identique, type JSON compris."""
    norm = sorted(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in rows)
    return hashlib.sha256("\n".join(norm).encode()).hexdigest()[:16]


def answer_of(cli, spec, win):
    """UNE réponse, réduite à ce qui est COMPARABLE : le corps rendu (valeurs pour un agrégat,
    empreinte + compte pour une matérialisation), le total de pagination, les drapeaux de
    complétude, et la ROUTE qui a servi. Aucune latence : ce fichier ne mesure pas le temps."""
    if spec.get("kind") == "search":
        params = f"?q={spec['q']}&limit=200"
        if win["frm"]:
            params += f"&from={win['frm']}"
        if win["to"]:
            params += f"&to={win['to']}"
        st, v = cli.call("/api/search" + params, method="GET")
        res = v.get("results") if isinstance(v, dict) else None
        if not isinstance(res, list):
            return dict(status=st, error=str(v)[:200])
        return dict(status=st, rows=len(res), digest=digest_rows(res),
                    coverage=(v.get("coverage") if isinstance(v, dict) else None))
    body = {"soql": spec["soql"], "from": win["frm"], "to": win["to"], "interactive": True}
    for k in ("limit", "offset", "keyset"):
        if spec.get(k) is not None:
            body[k] = spec[k]
    st, v = cli.call("/api/query", body)
    if st != 200 or not isinstance(v, dict) or "rows" not in v:
        msg = ""
        if isinstance(v, dict):
            msg = str(v.get("_error") or v.get("error") or v)[:300]
        return dict(status=st, error=msg)
    rows = v.get("rows") or []
    stats = v.get("stats") or {}
    out = dict(status=st, rows=len(rows), digest=digest_rows(rows),
               total=v.get("total"), truncated=bool(stats.get("truncated")),
               served_from=stats.get("served_from"))
    # Un agrégat tient en quelques lignes : on publie ses VALEURS, pas seulement leur empreinte —
    # c'est le chiffre que le lecteur veut pouvoir contredire (« 58 747 contre 289 »).
    if len(rows) <= 8:
        out["values"] = rows
    return out


# MIROIR de `PER_EVENT_STAGES` (daemon/src/cold_store/exactness.rs) — les étages GXQL dont chaque ligne
# de sortie est fonction d'UN SEUL événement. SYNC OBLIGATOIRE si la liste bouge côté daemon. Le défaut
# est le même des deux côtés : tout étage inconnu est SET-DERIVED.
PER_EVENT_STAGES = {"where", "head", "limit", "eval", "rex", "rename", "table", "fields"}


def is_set_derived(spec):
    """La réponse porte-t-elle une valeur calculée SUR L'ENSEMBLE (count/sum/dc/stats … by …) ?
    C'est la ligne de partage de l'invariant : sur un tel contrôle, une divergence est un NOMBRE FAUX,
    que le côté froid l'ait déclarée ou non. Sur les autres, une divergence déclarée est une réponse
    partielle honnête. La barre `/api/search` rend des lignes -> jamais set-derived."""
    if spec.get("kind") == "search":
        return False
    for stage in (spec.get("soql") or "").split("|")[1:]:
        cmd = stage.strip().split(" ")[0].lower()
        if cmd and cmd not in PER_EVENT_STAGES:
            return True
    return False


def verdict(hot, cold):
    """MÊME réponse ? Comparaison sur ce qui est OBSERVABLE par un client : le corps et le total.
    `truncated`/`served_from` sont du CONTEXTE (ils expliquent une divergence, ils ne la font pas).
    Un REFUS explicite d'un côté est sa propre catégorie : ce n'est ni la même réponse, ni un
    nombre faux."""
    if cold.get("status") not in (200, None) and hot.get("status") == 200:
        return "refused" if 400 <= (cold.get("status") or 0) < 500 else "differs"
    if hot.get("status") not in (200, None) and cold.get("status") == 200:
        return "refused" if 400 <= (hot.get("status") or 0) < 500 else "differs"
    if "error" in hot and "error" in cold:
        return "same"
    if hot.get("digest") == cold.get("digest") and hot.get("total") == cold.get("total"):
        return "same"
    # Divergence DITE : le côté froid signale son incomplétude (drapeau `truncated` ou note de
    # couverture). Ce n'est PAS un acquittement — un agrégat tronqué reste un nombre faux, déclaré ou
    # non ; c'est pourquoi les deux catégories sont comptées séparément et jamais additionnées.
    if cold.get("truncated") or cold.get("coverage"):
        return "declared"
    return "differs"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hot-base", required=True, help="daemon SANS tier froid (la référence)")
    p.add_argument("--cold-base", required=True, help="daemon AVEC tier froid (columnarisé)")
    p.add_argument("--host-header", default="localhost")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--end-ts", type=int, required=True)
    p.add_argument("--span-days", type=int, required=True)
    p.add_argument("--hot-window-days", type=int, required=True)
    p.add_argument("--retention-days", type=int, default=30)
    p.add_argument("--only", default="", help="préfixes de classes, séparés par des virgules")
    p.add_argument("--method", default="", help="phrase décrivant les DEUX bases (publiée telle quelle)")
    p.add_argument("--label", default="cold_parity")
    p.add_argument("-o", "--out", required=True)
    a = p.parse_args()

    hot_cli = Client(a.hot_base, a.user, a.password, a.host_header)
    cold_cli = Client(a.cold_base, a.user, a.password, a.host_header)
    kept, _dropped = windows(a.end_ts, a.span_days, a.hot_window_days, a.retention_days)
    specs = query_classes(a.end_ts)
    if a.only:
        pref = tuple(x.strip() for x in a.only.split(",") if x.strip())
        specs = [s for s in specs if s["id"].startswith(pref)]

    checks, counts = [], {"same": 0, "differs": 0, "declared": 0, "refused": 0, "nombre_faux": 0}
    for spec in specs:
        for win in kept:
            hot = answer_of(hot_cli, spec, win)
            cold = answer_of(cold_cli, spec, win)
            v = verdict(hot, cold)
            counts[v] += 1
            # LE COMPTE QUI COMPTE. Un agrégat qui diverge est un NOMBRE FAUX — le drapeau `truncated`
            # ne le rachète pas. On isole donc les contrôles SET-DERIVED dont la valeur diffère ET dont
            # le côté froid a quand même répondu 200 : c'est EXACTEMENT ce que l'invariant interdit.
            derived = is_set_derived(spec)
            false_number = derived and v in ("differs", "declared")
            if false_number:
                counts["nombre_faux"] += 1
            checks.append(dict(class_id=spec["id"], label=spec["label"], kind=spec.get("kind", "gxql"),
                               query=spec.get("soql") or spec.get("q"),
                               window=win["id"], window_from=win["frm"], window_to=win["to"],
                               verdict=v, set_derived=derived, false_number=false_number,
                               hot=hot, cold=cold))
            print(f"  {v:8s} {spec['id']:22s} {win['id']:12s} "
                  f"hot={hot.get('values') or hot.get('digest') or hot.get('error','')} "
                  f"cold={cold.get('values') or cold.get('digest') or cold.get('error','')}",
                  file=sys.stderr, flush=True)

    row = {"phase": a.label, "method": a.method, "counts": counts,
           "hot_window_days": a.hot_window_days, "span_days": a.span_days,
           "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "checks": checks}
    with open(a.out, "a") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"\nparité : {counts}", file=sys.stderr)


if __name__ == "__main__":
    main()
