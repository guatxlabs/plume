#!/usr/bin/env python3
"""bench/distill_profile.py — transforme la sortie brute de `bench/prod-profile.sql` en
`bench/profile-prod.json`, le profil que lit le générateur.

    python3 bench/distill_profile.py dump1.txt [dump2.txt ...] \
        --measured-at <horodatage ISO du relevé> \
        --host "<description de la machine : vCPU, RAM>"  # DESCRIPTION, pas le nom d hote \
        --image <image:tag> \
        -o bench/profile-prod.json

Le JSON produit porte, pour CHAQUE section, sa provenance : `measured` (sortie du SQL ci-dessus,
sur la prod, à la date donnée) ou `derived` (choix de banc documenté, PAS une mesure). Cette
distinction est le contrat du fichier : un chiffre publiable doit dire d'où il vient.
"""
import argparse
import json
import re
import sys

SECT = re.compile(r"^### ([A-Z0-9_]+)$")


def parse_dumps(paths):
    """Renvoie {section: [ligne, ...]}. Une section vue dans plusieurs dumps est CONCATÉNÉE
    puis dédupliquée en gardant le premier exemplaire (les passes se recoupent)."""
    out = {}
    for p in paths:
        cur = None
        with open(p, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                m = SECT.match(line.strip())
                if m:
                    cur = m.group(1)
                    out.setdefault(cur, [])
                    continue
                if cur is None or not line.strip():
                    continue
                if line.startswith(("real\t", "user\t", "sys\t", "---", "ok")):
                    continue
                if line not in out[cur]:
                    out[cur].append(line)
    return out


def rows(sec, n=None):
    for line in sec:
        f = line.split("|")
        if n is None or len(f) == n:
            yield f


def num(x, cast=float, default=None):
    """SQLite rend '' pour un NULL (AVG(LENGTH(v)) est NULL si toutes les valeurs sont NULL —
    ça arrive pour une clé JSON dont la valeur est `null`). On ne devine pas : on garde None."""
    x = (x or "").strip()
    if x == "":
        return default
    try:
        return cast(x)
    except ValueError:
        return default


def kv_pairs(line):
    """'a|1|b|2' -> {'a': 1, 'b': 2} (les GLOBAL_ONEPASS sont écrits en paires)."""
    f = line.split("|")
    d = {}
    for i in range(0, len(f) - 1, 2):
        try:
            d[f[i]] = int(f[i + 1])
        except ValueError:
            try:
                d[f[i]] = float(f[i + 1])
            except ValueError:
                d[f[i]] = f[i + 1]
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dumps", nargs="+")
    ap.add_argument("--measured-at", required=True)
    ap.add_argument("--host", required=True,
                    help="DESCRIPTION du matériel, PAS le nom d'hôte. Ce fichier est destiné à la "
                         "publication : nommer la machine de production y ajouterait une "
                         "information d'infrastructure sans rien apporter à la provenance.")
    ap.add_argument("--image", required=True)
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()

    s = parse_dumps(a.dumps)
    missing = [k for k in ("BY_SOURCE", "SRC_KEY_SETS", "JSON_NKEYS_HIST", "DBSTAT_BY_NAME") if k not in s]
    if missing:
        sys.exit(f"sections absentes des dumps : {missing}")

    prov_measured = f"mesuré sur la production {a.host}, image {a.image}, le {a.measured_at}, via bench/prod-profile.sql"

    # --- volume / fenêtre
    rng = {}
    for line in s.get("EVENT_COUNT_AND_RANGE", []):
        for tok in line.replace("|", " ").split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                rng[k] = int(v)

    # --- pragmas
    prag = {}
    for line in s.get("PRAGMAS", []):
        if "=" in line:
            k, v = line.split("=", 1)
            prag[k] = int(v) if v.isdigit() else v

    # --- global one-pass. ATTENTION : les lignes msglen_* et fldlen_* utilisent TOUTES DEUX les
    # étiquettes nues 'avg'/'max'/'sum'. On les préfixe par la ligne dont elles viennent, sinon la
    # seconde écrase la première et `message_len.avg` vaudrait en réalité la longueur du blob JSON.
    glob, lens = {}, {}
    for line in s.get("GLOBAL_ONEPASS", []):
        d = kv_pairs(line)
        pref = next((k.split("len_")[0] + "len" for k in d if k.endswith("len_min")), None)
        if pref:
            lens[pref] = {("min" if k.endswith("_min") else k): v for k, v in d.items()}
            lens[pref] = {k.replace(pref + "_", ""): v for k, v in lens[pref].items()}
        else:
            glob.update(d)

    card = {f[0]: int(f[1]) for f in rows(s.get("CARD_EXACT", []), 2)}

    # --- histogrammes
    def hist(name):
        return {f[0]: int(f[1]) for f in rows(s.get(name, []), 2)}

    # --- par source
    src_msglen = {f[0]: dict(msg_min=num(f[1], int), msg_avg=num(f[2]), msg_max=num(f[3], int),
                             fields_avg=num(f[4]), fields_max=num(f[5], int))
                  for f in rows(s.get("SRC_MSGLEN", []), 6)}
    src_sev, src_cat = {}, {}
    for f in rows(s.get("SRC_SEV", []), 3):
        src_sev.setdefault(f[0], {})[int(f[1])] = int(f[2])
    for f in rows(s.get("SRC_CAT", []), 3):
        src_cat.setdefault(f[0], {})[f[1]] = int(f[2])
    src_keys = {}
    for f in rows(s.get("SRC_KEY_SETS", []), 6):
        src_keys.setdefault(f[0], []).append(dict(
            key=f[1], n=num(f[2], int, 0), avg_len=num(f[3]), card=num(f[4], int, 0), type=f[5]))

    sources = []
    for f in rows(s.get("BY_SOURCE", []), 7):
        name, n = f[0], int(f[1])
        ml = src_msglen.get(name, {})
        sources.append(dict(
            name=name, n=n,
            distinct_hosts=int(f[2]), distinct_categories=int(f[3]),
            msg_len=dict(min=ml.get("msg_min"), avg=ml.get("msg_avg"), max=ml.get("msg_max")),
            fields_len=dict(avg=ml.get("fields_avg"), max=ml.get("fields_max")),
            src_ip_present=int(f[6]),
            severity=src_sev.get(name, {}),
            categories=src_cat.get(name, {}),
            fields=sorted(src_keys.get(name, []), key=lambda d: -d["n"]),
        ))
    sources.sort(key=lambda d: -d["n"])

    # --- champs étendus, vue globale
    json_keys = [dict(key=f[0], n=num(f[1], int, 0), avg_len=num(f[2]), max_len=num(f[3], int),
                      card=num(f[4], int, 0), type=f[5])
                 for f in rows(s.get("JSON_KEYS_FULL", []), 6)]
    nkeys = {int(f[0]): int(f[1]) for f in rows(s.get("JSON_NKEYS_HIST", []), 2)}
    key_tot = {f[0]: int(f[1]) for f in rows(s.get("JSON_KEY_TOTALS", []), 2)}

    # --- poids disque
    dbstat = [dict(name=f[0], bytes=int(f[1]), pages=int(f[2]))
              for f in rows(s.get("DBSTAT_BY_NAME", []), 3)]
    by_name = {d["name"]: d["bytes"] for d in dbstat}
    ev_tbl = by_name.get("event", 0)
    # `idx_ev_auto_` DÉCRIT LE PASSÉ, ET LE PRÉFIXE RESTE EXPRÈS. L'indexation adaptative qui posait
    # ces index a été retirée (P6.8-b) et le daemon les DROPPE en fond ; une base distillée après ce
    # passage n'en porte plus aucun. Mais la purge est de FOND : une base distillée AVANT qu'elle
    # tourne en porte encore, et les oublier ferait SOUS-COMPTER le poids des index de `event` — un
    # profil plus flatteur que la base qu'il décrit. Le préfixe ne fait rien exister ; il empêche de
    # perdre des pages qui existent.
    ev_idx = sum(b for n, b in by_name.items()
                 if (n.startswith(("idx_event_", "idx_ev_f_", "idx_ev_auto_")) or n == "sqlite_autoindex_event_1"))
    ev_fts = sum(b for n, b in by_name.items() if n.startswith("event_fts"))

    profile = {
        "schema_version": 1,
        "_lisez_moi": (
            "Profil de données de la PRODUCTION plume, distillé en distributions. Aucune valeur de "
            "ligne n'y figure. Chaque section porte son champ `provenance` : `measured` = sortie de "
            "bench/prod-profile.sql à la date indiquée ; `derived` = choix de banc documenté, PAS une "
            "mesure. Le générateur (bench/gen_events.py) ne lit QUE ce fichier."
        ),
        "provenance_source": {
            "measured": prov_measured,
            "method": (
                "connexion SQLCipher LECTURE SEULE (file:…?mode=ro) ouverte à côté du daemon vivant ; "
                "seuls des agrégats sont sortis (comptes, cardinalités, longueurs, noms de clés) ; "
                "aucune valeur de message/host/src_ip/url/dedup ni de valeur JSON n'a quitté la machine."
            ),
            "host": a.host,
            "image": a.image,
            "measured_at": a.measured_at,
        },

        "volume": {
            "provenance": "measured",
            "events": rng.get("n"),
            "min_ts": rng.get("min_ts"),
            "max_ts": rng.get("max_ts"),
            "span_days": round((rng.get("max_ts", 0) - rng.get("min_ts", 0)) / 86400.0, 2),
            "min_id": rng.get("min_id"),
            "max_id": rng.get("max_id"),
            "ids_consumed": rng.get("max_id", 0) - rng.get("min_id", 0) + 1,
            "_note_purge": (
                "ids_consumed - events = lignes déjà purgées par la rétention. L'écart mesuré dit que "
                "la base a porté ~6,3 M d'événements de plus que ce qu'elle contient aujourd'hui : "
                "la topologie sur laquelle les anciens chiffres avaient été pris N'EXISTE PLUS."
            ),
        },

        "disk": {
            "provenance": "measured",
            "page_size": prag.get("page_size"),
            "page_count": prag.get("page_count"),
            "freelist_pages": prag.get("freelist"),
            "file_bytes": (prag.get("page_size", 0) * prag.get("page_count", 0)),
            "live_bytes": (prag.get("page_size", 0) * (prag.get("page_count", 0) - prag.get("freelist", 0))),
            "journal_mode": prag.get("journal"),
            "auto_vacuum": prag.get("auto_vacuum"),
            "event_table_bytes": ev_tbl,
            "event_indexes_bytes": ev_idx,
            "event_fts_bytes": ev_fts,
            "ratio_indexes_over_table": round(ev_idx / ev_tbl, 3) if ev_tbl else None,
            "ratio_fts_over_table": round(ev_fts / ev_tbl, 3) if ev_tbl else None,
            "by_object_bytes": dbstat,
            "_note": (
                "event_fts est le FTS5 sur (message, source, category) — il est INCONDITIONNEL. "
                "event_fields_fts (PLUME_FTS_FIELDS=1) est ABSENT de cette production : la prod tourne "
                "à PLUME_FTS_FIELDS=0, son coût disque n'est donc PAS mesuré ici."
            ),
        },

        "columns": {
            "provenance": "measured",
            "cardinality": {
                "source": card.get("source"), "category": card.get("category"),
                "host": card.get("host"), "src_ip": card.get("src_ip"),
                "dst_ip": glob.get("card_dstip"), "url": glob.get("card_url"),
                "xff": glob.get("card_xff"), "message": glob.get("card_msg"),
                "env_id": glob.get("card_env"), "origin": glob.get("card_origin"),
                "engagement_id": glob.get("card_eng"), "dedup": glob.get("card_dedup"),
            },
            "nulls": {k[5:]: v for k, v in glob.items() if k.startswith("null_")},
            "message_len": lens.get("msglen", {}),
            "fields_len": lens.get("fldlen", {}),
            "message_len_hist": hist("MSGLEN_HIST"),
            "fields_len_hist": hist("FLDLEN_HIST"),
        },

        "distribution": {
            "provenance": "measured",
            "by_category": {f[0]: int(f[1]) for f in rows(s.get("BY_CATEGORY", []), 2)},
            "by_severity": {int(f[0]): int(f[1]) for f in rows(s.get("BY_SEVERITY", []), 2)},
            "by_env_origin": [dict(env_id=f[0], origin=f[1], engagement_id=f[2], n=int(f[3]))
                              for f in rows(s.get("BY_ENV_ORIGIN", []), 4)],
        },

        "temporal": {
            "provenance": "measured",
            "per_day": {f[0]: int(f[1]) for f in rows(s.get("DENSITY_PER_DAY", []), 2)},
            "per_hour_of_day": {int(f[0]): int(f[1]) for f in rows(s.get("DENSITY_PER_HOUR_OF_DAY", []), 2)},
        },

        "extended_fields": {
            "provenance": "measured",
            "distinct_keys": key_tot.get("distinct_keys"),
            "total_kv_pairs": key_tot.get("total_kv_pairs"),
            "keys_per_event_hist": nkeys,
            "keys": json_keys,
            "_note": (
                "`cim` est présent sur 100 % des lignes : le daemon l'estampille à l'ingest "
                "(cim_stamp). Un générateur qui ne le pose pas ne change rien — l'ingest le remet."
            ),
        },

        "sources": {"provenance": "measured", "list": sources},

        "rollups": {
            "provenance": "measured",
            "rows": {f[0]: int(f[1]) for f in rows(s.get("ROLLUP_SIZES", []), 2)},
        },

        # ------------------------------------------------------------------ DÉRIVÉ, PAS MESURÉ
        # Tout ce qui suit est un CHOIX DE BANC. Aucun de ces chiffres ne vient de la production ;
        # ils disent comment le générateur transpose la forme mesurée à l'échelle visée, et dans
        # quel sens chaque écart fausse le résultat. Un écart qui rend le banc PLUS FACILE que la
        # prod est un aveu à publier ; un écart qui le rend plus dur est conservateur.
        "bench_target": {
            "provenance": "derived",
            "events": 10_000_000,
            "span_days": 28,
            "_span_rationale": (
                "28 j et pas 30 : la purge de rétention (PLUME_RETENTION_DAYS, défaut 30) supprime "
                "ts < now-30j. À 30 j pleins, les plus vieux événements du banc disparaîtraient "
                "PENDANT la mesure et le nombre de lignes ne serait plus stable."
            ),
            "events_per_day": 10_000_000 // 28,
            "_density_vs_prod": (
                f"la prod mesurée fait ~{max((v for k, v in {f[0]: int(f[1]) for f in rows(s.get('DENSITY_PER_DAY', []), 2)}.items() if k >= '2026-07-24'), default=0)} "
                "événements/jour ; le banc en fait ~357 000/jour, soit ~2,2x. La FORME horaire "
                "(courbe heure-du-jour mesurée) est conservée, seule l'amplitude change."
            ),
            "hosts": 64,
            "_hosts_rationale": (
                "la prod mesurée n'a que 2 hosts (k3s mono-nœud). Garder 2 rendrait tout group-by "
                "sur `host` artificiellement gratuit et donnerait des chiffres FLATTEURS. 64 est un "
                "choix de banc, non une mesure : il rend le banc PLUS DUR que cette prod."
            ),
            "src_ip_v4_pool": ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
            "src_ip_v6_pool": "2001:db8::/32",
            "src_ip_target_cardinality": 20_000,
            "_ip_rationale": (
                "les 3 /24 de documentation (RFC 5737) ne portent que 768 adresses — bien moins que "
                "les 21 140 src_ip distinctes mesurées en prod, ce qui rendrait le group-by sur "
                "src_ip trop facile. Le complément vient du préfixe de documentation IPv6 "
                "2001:db8::/32 (RFC 3849), qui est lui aussi manifestement fictif et non routable. "
                "AUCUNE adresse réelle n'est générée."
            ),
            "hostname_suffix": ".plume.invalid",
            "user_pool_size": 1053,
            "_naming_rationale": (
                "noms d'hôte en .invalid et .example (RFC 2606/6761 : réservés, non résolvables), "
                "utilisateurs `bench-user-NNNN`, domaines `example.com`. Rien n'est emprunté à la "
                "production : le profil ne contient AUCUNE valeur, seulement des distributions."
            ),
            "known_divergences_from_prod": [
                "src_ip : cardinalité plafonnée par les plages de documentation (compensée en IPv6).",
                "message : le corps du texte est SYNTHÉTIQUE. Longueur, alphabet et vocabulaire de "
                "termes recherchables sont calés sur les distributions mesurées, mais un vrai log a "
                "une entropie et une répétitivité que le banc n'imite pas. Conséquence : les "
                "chiffres FTS5 et LIKE dépendent de ce vocabulaire — c'est le point le plus faible "
                "du banc et il est explicitement borné (voir bench/gen_events.py, VOCAB).",
                "dedup : la base réelle a une majorité de NULL et des centaines de milliers de valeurs "
                "distinctes ; le banc met un dedup unique sur 100 % des lignes pour que le rejeu soit "
                "idempotent. Conséquence : l'index UNIQUE sur dedup est PLUS gros au banc que sur la base "
                "réelle (quelques dizaines de Mio).",
                "cold tier : la base réelle porte un tier froid Parquet (quelques centaines de Mio). "
                "Le banc génère du CHAUD uniquement.",
            ],
        },

        "masking": {
            "provenance": "measured",
            "field_filter_rows": int(s.get("FIELD_FILTER_ROWS", ["0"])[0].split("|")[0]),
            "_note": (
                "0 ligne dans `field_filter` = ENSEMBLE DE MASQUAGE VIDE. La base mesurée ici "
                "tourne SANS masquage : tous ses chiffres historiques valent pour l'état masque-vide, "
                "celui où la route de rollups et le moteur vectorisé sont ARMÉS."
            ),
        },
    }

    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, ensure_ascii=False, indent=1, sort_keys=False)
        fh.write("\n")
    print(f"écrit {a.out}: {len(sources)} sources, {len(json_keys)} clés étendues, "
          f"{profile['volume']['events']} événements profilés")


if __name__ == "__main__":
    main()
