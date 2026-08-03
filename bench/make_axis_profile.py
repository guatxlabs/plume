#!/usr/bin/env python3
"""bench/make_axis_profile.py — DÉRIVE un profil qui ne diffère du mesuré que par UN axe.

LE TROU QU'IL BOUCHE
  `bench/make_fleet_profile.py` fait varier UN paramètre du jeu de données : le nombre de machines.
  C'était le biais le plus fort de la production profilée, mais ce n'est pas le seul. Un chiffre
  mesuré sur NOTRE profil ne prouve pas qu'un tiers obtiendra le même : il prouve notre cas. Pour
  savoir si un chiffre TIENT ailleurs, il faut le remesurer sur des jeux qui diffèrent, et publier
  l'écart. Ce script produit ces jeux.

LES AXES SONT DÉRIVÉS DU CHEMIN D'EXÉCUTION, PAS CHOISIS
  Chaque axe correspond à une DÉCISION du daemon dont la donnée — et non la requête — décide :

  `--ext-card-scale S`   Multiplie la CARDINALITÉ des clés étendues (le JSON `fields`).
                         Décision visée : `soql_glue.rs` n'émet un accès indexé que pour les 10
                         clés de `HOT_FIELDS` (`action, user, owner, kind, ns, role, scope, verb,
                         resource, operation`) ; toute autre clé se lit par `json_extract` en scan.
                         La cardinalité décide, elle, la SÉLECTIVITÉ de l'accès indexé et le nombre
                         de groupes d'un `group by`. Mesuré chez nous : `action` a une cardinalité
                         de 4 et `user` de 1008 — un client dont le vocabulaire d'action est large
                         n'a ni le même `event_rollup` ni le même coût de group-by.
                         EXCLUS de la mise à l'échelle, et c'est délibéré : `src_ip`, `dst_ip`,
                         `url`, `rhost` — le daemon les PROMEUT en vraies colonnes à l'ingest
                         (`parsers.rs::fields_promote_src_dst_url`). Les faire varier ici
                         mélangerait deux mécanismes et l'écart mesuré ne serait attribuable à
                         aucun des deux.

  `--event-size-scale S` Multiplie la LONGUEUR du message et des valeurs de champs étendus.
                         Décision visée : aucune — et c'est le point. Aucun index ne porte sur
                         `message` ni sur `fields` (`db/schema.sql`) ; tout filtre sur eux est un
                         scan, dont le coût est proportionnel aux OCTETS lus. La taille d'événement
                         décide donc le coût de tout ce qui scanne, et la taille de la base.

  `--severity-shift F`   Déplace la masse de la distribution de sévérité vers `>= 3`, F étant la
                         fraction visée. Décision visée : `rollups.rs` ne retient `src_ip` comme
                         DIMENSION de `event_rollup` que si `severity >= PLUME_ROLLUP_SRCIP_MIN_SEV`
                         (défaut 3) — sinon la valeur est ramenée à `''` — puis plafonne à un top-N
                         par bucket. La distribution de sévérité du jeu décide donc si les rollups
                         par `src_ip` sont peuplés ou vides, c'est-à-dire si une requête peut être
                         servie par la route de rollups ou doit scanner. Mesuré chez nous :
                         6,4 % des événements ont `severity >= 3`.

  `--rename-sources SUF` Suffixe le NOM de chaque source. RIEN d'autre ne bouge : ni volume, ni
                         cardinalité, ni sévérité, ni longueur. C'est l'axe le plus pur du lot, et
                         le plus gênant. Décision visée : `rollups.rs::DIM_ROLLUP_SPECS` est une
                         table EN DUR de couples (nom de source, dimension) — `web`->status/vhost/
                         path, `auditd`->exe/comm/auid/key/action, `kube-audit`->verb/user/...
                         Un `search source=X | stats count by d` n'est servi par le rollup par
                         dimension QUE si le couple (X, d) y figure (`rollup_route.rs`, route B).
                         Or notre profil porte les noms de sources de NOTRE production, qui sont
                         exactement les clés de cette table. Un tiers dont les sources s'appellent
                         autrement n'a aucune couverture — la même requête scanne.

  `--source-mix M`       `as-measured` | `uniforme`. Décision visée : `idx_event_src_ts(source,ts)`.
                         La sélectivité d'un filtre `source=X` est le POIDS de X dans le flux. Chez
                         nous une seule source pèse 38,5 % ; répartir uniformément change la
                         sélectivité de toutes les classes qui nomment une source.

CE QU'IL REFUSE DE FAIRE
  Deux axes à la fois. Un profil qui diffère du témoin sur deux paramètres ne mesure ni l'un ni
  l'autre : l'écart observé n'est attribuable à rien. Le script s'arrête si on lui en demande deux.

CE QU'IL NE PRÉTEND PAS ÊTRE
  Ces profils sont SYNTHÉTIQUES et DÉRIVÉS. Ils ne sont la production de personne. Ils répondent à
  « le chiffre bouge-t-il quand ce paramètre bouge, et de combien », ce qui est la seule question à
  laquelle un banc puisse répondre sans les données du tiers. Ils ne répondent PAS à « voici ce que
  mesurera tel client » — cette phrase-là exigerait son jeu, pas le nôtre.

USAGE
  python3 bench/make_axis_profile.py --ext-card-scale 25 -o bench/profile-card-haute.json
  python3 bench/make_axis_profile.py --event-size-scale 3 -o bench/profile-taille-grande.json
  python3 bench/make_axis_profile.py --severity-shift 0.6 -o bench/profile-sev-haute.json
  python3 bench/make_axis_profile.py --source-mix uniforme -o bench/profile-mix-uniforme.json
"""
import argparse
import hashlib
import json
import os
import sys

# Clés que le daemon PROMEUT en vraies colonnes à l'ingest (parsers.rs::fields_promote_src_dst_url).
# Les exclure de l'axe « cardinalité des clés étendues » n'est pas une commodité : leur cardinalité
# agit par un AUTRE chemin (une colonne indexée, plus la dimension `src_ip` des rollups), et un
# profil qui bougerait les deux à la fois ne permettrait d'attribuer l'écart à aucun des deux.
PROMOTED_KEYS = {"src_ip", "dst_ip", "url", "rhost"}

# Les 10 clés étendues qui reçoivent un index d'expression (soql_glue.rs::HOT_FIELDS, créés par
# maintenance.rs sous PLUME_EXPRINDEX=1). Recopiées ici POUR ÊTRE PUBLIÉES dans le profil, pas pour
# décider quoi que ce soit : le script ne les traite pas autrement que les autres.
HOT_FIELDS = ["action", "user", "owner", "kind", "ns", "role", "scope", "verb",
              "resource", "operation"]


def scale_ext_cardinality(p, scale):
    """Multiplie la cardinalité de chaque clé étendue NON promue. Plancher à 1 : une cardinalité
    nulle n'a pas de sens et ferait disparaître la clé du jeu."""
    touched, skipped = 0, set()
    for s in p["sources"]["list"]:
        for f in s.get("fields") or []:
            if f["key"] in PROMOTED_KEYS:
                skipped.add(f["key"])
                continue
            old = f.get("card") or 1
            f["card"] = max(1, int(round(old * scale)))
            touched += 1
    return touched, sorted(skipped)


def scale_event_size(p, scale):
    """Multiplie les longueurs de message ET les longueurs moyennes de valeurs de champs étendus.
    `min` suit aussi : une borne basse laissée en place écraserait l'effet sur les sources courtes."""
    touched = 0
    for s in p["sources"]["list"]:
        ml = s.get("msg_len")
        if ml:
            for k in ("min", "avg", "max"):
                if ml.get(k):
                    ml[k] = max(1, int(round(ml[k] * scale)))
            touched += 1
        for f in s.get("fields") or []:
            if f.get("avg_len"):
                f["avg_len"] = max(1, int(round(f["avg_len"] * scale)))
    return touched


def shift_severity(p, frac):
    """Redistribue, PAR SOURCE, la masse de sévérité pour que la fraction `>= 3` vaille `frac`.
    La FORME à l'intérieur de chaque groupe (0..2 et 3..4) est préservée : on déplace de la masse
    entre les deux groupes, on n'invente pas une distribution."""
    for s in p["sources"]["list"]:
        sev = {int(k): v for k, v in (s.get("severity") or {}).items()}
        if not sev:
            continue
        tot = sum(sev.values()) or 1
        lo = {k: v for k, v in sev.items() if k < 3}
        hi = {k: v for k, v in sev.items() if k >= 3}
        # Une source qui n'a AUCUNE sévérité haute mesurée n'en reçoit pas : lui en inventer une
        # fabriquerait une source qui n'existe pas. Le taux global visé est donc approché, pas
        # atteint — et c'est le taux RÉEL qui est publié dans la section `axis` du profil.
        if not hi or not lo:
            continue
        want_hi = tot * frac
        want_lo = tot - want_hi
        khi = want_hi / (sum(hi.values()) or 1)
        klo = want_lo / (sum(lo.values()) or 1)
        for k in hi:
            sev[k] = max(0, int(round(sev[k] * khi)))
        for k in lo:
            sev[k] = max(0, int(round(sev[k] * klo)))
        s["severity"] = {str(k): v for k, v in sev.items() if v > 0}
    return severity_fraction(p)


def severity_fraction(p):
    """Fraction MESURÉE sur le profil (après retouche) des événements de sévérité >= 3, pondérée
    par le poids de chaque source. C'est ce chiffre-là qui est publié, jamais la consigne."""
    num = den = 0.0
    for s in p["sources"]["list"]:
        sev = {int(k): v for k, v in (s.get("severity") or {}).items()}
        tot = sum(sev.values()) or 1
        w = s["n"] / tot
        for k, v in sev.items():
            den += v * w
            if k >= 3:
                num += v * w
    return round(num / den, 4) if den else 0.0


def uniform_source_mix(p):
    """Même poids `n` pour toutes les sources, à VOLUME TOTAL CONSTANT. Le volume total ne doit pas
    bouger : sinon la passe mesurerait aussi un changement de volume."""
    srcs = p["sources"]["list"]
    tot = sum(s["n"] for s in srcs)
    each = tot // len(srcs)
    for s in srcs:
        # `n` est le dénominateur des taux de présence (`fields[].n`, `src_ip_present`). Les
        # réajuster garde chaque taux inchangé — seul le POIDS de la source bouge.
        old = s["n"] or 1
        k = each / old
        for f in s.get("fields") or []:
            f["n"] = max(0, int(round(f["n"] * k)))
        if s.get("src_ip_present"):
            s["src_ip_present"] = max(0, int(round(s["src_ip_present"] * k)))
        s["n"] = each
    return len(srcs), each


def rename_sources(p, suffix):
    """Suffixe le nom de chaque source. Le seul axe du lot dont on puisse dire qu'il ne change
    STRICTEMENT rien d'autre : ni un poids, ni une cardinalité, ni une longueur, ni une sévérité.
    Ce qu'il change est un NOM — et c'est justement ce dont dépend la couverture des rollups par
    dimension, qui est écrite en dur dans le daemon."""
    names = []
    for s in p["sources"]["list"]:
        old = s["name"]
        s["name"] = f"{old}{suffix}"
        names.append((old, s["name"]))
    return names


def top_source_share(p):
    srcs = p["sources"]["list"]
    tot = sum(s["n"] for s in srcs) or 1
    return round(max(s["n"] for s in srcs) / tot, 4)


def ext_card_stats(p):
    """Cardinalité MESURÉE sur le profil produit, par clé étendue non promue (max sur les sources).
    Publiée pour que la section `axis` porte un chiffre relu du profil, pas la consigne reçue."""
    agg = {}
    for s in p["sources"]["list"]:
        for f in s.get("fields") or []:
            if f["key"] in PROMOTED_KEYS:
                continue
            agg[f["key"]] = max(agg.get(f["key"], 0), f.get("card") or 1)
    if not agg:
        return {}
    vals = sorted(agg.values())
    return {"n_keys": len(agg), "card_min": vals[0], "card_max": vals[-1],
            "card_median": vals[len(vals) // 2],
            "hot_fields_card": {k: agg[k] for k in HOT_FIELDS if k in agg}}


def mean_event_bytes(p):
    """Longueur moyenne PONDÉRÉE (message + valeurs de champs étendus), relue sur le profil."""
    num = den = 0.0
    for s in p["sources"]["list"]:
        n = s["n"] or 0
        ml = (s.get("msg_len") or {}).get("avg") or 0
        fl = sum((f.get("avg_len") or 0) * (f["n"] / max(s["n"], 1))
                 for f in s.get("fields") or [])
        num += n * (ml + fl)
        den += n
    return round(num / den, 1) if den else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=os.path.join(os.path.dirname(__file__), "profile-prod.json"))
    ap.add_argument("--ext-card-scale", type=float, default=None,
                    help="facteur sur la cardinalité des clés étendues NON promues")
    ap.add_argument("--event-size-scale", type=float, default=None,
                    help="facteur sur la longueur des messages et des valeurs de champs")
    ap.add_argument("--severity-shift", type=float, default=None,
                    help="fraction visée d'événements de sévérité >= 3 (gate rollup src_ip)")
    ap.add_argument("--source-mix", choices=["as-measured", "uniforme"], default=None)
    ap.add_argument("--rename-sources", default=None,
                    help="suffixe appliqué au NOM de chaque source (et rien d'autre)")
    ap.add_argument("--events", type=int, default=None, help="bench_target.events du profil produit")
    ap.add_argument("-o", "--out", help="fichier JSON à écrire")
    a = ap.parse_args()

    asked = [("ext_card_scale", a.ext_card_scale), ("event_size_scale", a.event_size_scale),
             ("severity_shift", a.severity_shift),
             ("rename_sources", a.rename_sources),
             ("source_mix", a.source_mix if a.source_mix != "as-measured" else None)]
    active = [(k, v) for k, v in asked if v is not None]
    if len(active) != 1:
        sys.exit("EXACTEMENT un axe par profil. Un profil qui diffère du témoin sur deux "
                 "paramètres ne mesure ni l'un ni l'autre : l'écart observé ne serait "
                 f"attribuable à rien. Demandé : {[k for k, _ in active] or 'aucun'}.")
    axis, value = active[0]

    raw = open(a.profile, "rb").read()
    p = json.loads(raw.decode("utf-8"))
    src_sha = hashlib.sha256(raw).hexdigest()

    before = {"ext_card": ext_card_stats(p), "mean_value_bytes": mean_event_bytes(p),
              "severity_ge3_frac": severity_fraction(p), "top_source_share": top_source_share(p)}

    detail = {}
    if axis == "ext_card_scale":
        touched, skipped = scale_ext_cardinality(p, value)
        detail = {"fields_touched": touched, "keys_excluded_promoted": skipped}
    elif axis == "event_size_scale":
        detail = {"sources_touched": scale_event_size(p, value)}
    elif axis == "severity_shift":
        detail = {"severity_ge3_frac_effective": shift_severity(p, value)}
    elif axis == "rename_sources":
        pairs = rename_sources(p, value)
        detail = {"renamed": len(pairs), "exemples": [f"{o} -> {n}" for o, n in pairs[:5]]}
    elif axis == "source_mix":
        nsrc, each = uniform_source_mix(p)
        detail = {"sources": nsrc, "n_per_source": each}

    after = {"ext_card": ext_card_stats(p), "mean_value_bytes": mean_event_bytes(p),
             "severity_ge3_frac": severity_fraction(p), "top_source_share": top_source_share(p)}

    if a.events:
        p["bench_target"]["events"] = a.events

    # La provenance change : ces sources ne sont plus « mesurées », elles sont dérivées d'une mesure.
    # Le dire est le minimum ; le cacher rendrait le profil indiscernable d'un profil de production.
    p["sources"]["provenance"] = "derived"
    p["sources"]["_derived_note"] = (
        f"cardinalités/longueurs/poids retouchés par bench/make_axis_profile.py sur l'axe {axis}. "
        "Les distributions de départ sont mesurées ; leur mise à l'échelle ne l'est pas.")
    p["axis"] = {
        "provenance": "derived",
        "axis": axis,
        "value": value,
        "detail": detail,
        "source_profile_sha256": src_sha,
        "before": before,
        "after": after,
        "_note": ("`before`/`after` sont RELUS sur le profil, pas recopiés de la consigne : "
                  "si une retouche n'a pas mordu, l'écart entre les deux le montre."),
    }

    out = json.dumps(p, ensure_ascii=False, indent=1)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"écrit : {a.out}")
    else:
        print(out)
    print(f"axe {axis} = {value}")
    for k in ("severity_ge3_frac", "top_source_share", "mean_value_bytes"):
        print(f"  {k:22} {before[k]}  ->  {after[k]}")
    print(f"  ext_card median         {before['ext_card'].get('card_median')}"
          f"  ->  {after['ext_card'].get('card_median')}")


if __name__ == "__main__":
    main()
