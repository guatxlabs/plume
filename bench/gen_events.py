#!/usr/bin/env python3
"""bench/gen_events.py — GÉNÉRATEUR DÉTERMINISTE d'événements au profil de la production.

CE QU'IL GARANTIT
  * DÉTERMINISME TOTAL : PRNG splitmix64 à graine explicite, écrit ici, pas celui de la
    bibliothèque standard (dont les internes peuvent changer d'une version de Python à l'autre).
    Aucun appel à l'horloge : le temps est le paramètre `--end-ts`. Mêmes paramètres -> MÊMES
    OCTETS. `--digest` imprime le SHA-256 du flux : c'est la preuve, vérifiable par un tiers.
  * ZÉRO DONNÉE RÉELLE : adresses IPv4 dans les seules plages de documentation de la RFC 5737
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), IPv6 dans 2001:db8::/32 (RFC 3849),
    noms d'hôte en `.plume.invalid` (RFC 2606/6761 : réservé, non résolvable), utilisateurs
    `bench-user-NNNN`. Le profil lu (bench/profile-prod.json) ne contient QUE des distributions.
  * CHAMPS ÉTENDUS REMPLIS : le blob JSON `fields` est peuplé au jeu de clés MESURÉ PAR SOURCE
    (241 clés distinctes en prod, ~7,6 par événement), avec les longueurs et cardinalités
    mesurées. La question posée porte sur « tous les champs » : un générateur qui ne remplirait
    que les colonnes CIM cœur ne mesurerait pas ce qu'on prétend mesurer.

AIGUILLES PLANTÉES (indispensables à un banc reproductible)
  Une requête de recherche n'a de sens que si sa SÉLECTIVITÉ est connue. Trois marqueurs sont
  plantés à taux exact, et `--manifest` les écrit :
    NEEDLE_MSG_RARE   dans `message`      1 / 1 000
    NEEDLE_MSG_COMMON dans `message`      1 / 10
    NEEDLE_FLD        dans `fields.needle` 1 / 500   (champ ÉTENDU : le cas coûteux)

CHEMIN D'INGEST
  Par défaut le générateur POSTe sur `/api/ingest` — le VRAI chemin (auth, garde de host, garde
  disque, cap d'événements, spool, puis normalisation / promotion de colonnes / cim_stamp /
  déclencheurs FTS / index d'expression). C'est le seul mode dont les chiffres décrivent le
  produit. `--out-dir` (fichiers) et `--digest` (empreinte) ne servent qu'à l'inspection et à la
  preuve de déterminisme.

USAGE
  python3 bench/gen_events.py --count 10000000 --end-ts 1785400000 \
      --post http://127.0.0.1:7000/api/ingest --token "$TOK" --spool-dir /chemin/spool
  python3 bench/gen_events.py --count 100000 --end-ts 1785400000 --digest
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from hashlib import sha256

# ------------------------------------------------------------------ PRNG (écrit ici, pas importé)
MASK64 = (1 << 64) - 1


class Rng:
    """splitmix64 — 1 multiplication + 2 xorshift par tirage, séquence entièrement spécifiée par
    la graine. Choisi pour que le flux soit reproductible hors de Python aussi (le réimplémenter
    en Rust ou en Go donne la même suite)."""

    __slots__ = ("s",)

    def __init__(self, seed):
        self.s = seed & MASK64

    def next(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & MASK64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)

    def below(self, n):
        return self.next() % n if n > 0 else 0

    def frac(self):
        """[0,1) sur 53 bits."""
        return (self.next() >> 11) * (1.0 / (1 << 53))

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def weighted(self, keys, cumw, total):
        r = self.below(total)
        lo, hi = 0, len(cumw) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if r < cumw[mid]:
                hi = mid
            else:
                lo = mid + 1
        return keys[lo]


def cumulative(weights):
    cum, acc = [], 0
    for w in weights:
        acc += max(int(w), 0)
        cum.append(acc)
    return cum, acc


# ------------------------------------------------------------------ vocabulaire synthétique
# LIMITE ASSUMÉE : un vrai journal a une entropie et une répétitivité que ce vocabulaire n'imite
# pas. Les chiffres FTS5 / LIKE / REGEXP en dépendent donc directement. C'est le point faible du
# banc, il est nommé ici et dans docs/BENCHMARK.md — pas caché.
VOCAB = (
    "session opened closed accepted failed denied allowed blocked dropped invalid expired "
    "connection request response timeout retry refused reset established teardown handshake "
    "policy rule match verdict quarantine escalate suppress threshold baseline deviation "
    "process exec spawn fork exit signal segfault oom killed restarted reloaded reconciled "
    "volume mount unmount snapshot backup restore checkpoint compaction vacuum rollup "
    "token bearer scope claim audience issuer revoked rotated renewed leased sealed "
    "packet flow ingress egress upstream downstream proxy tunnel route hop mtu "
    "bucket object prefix multipart etag lifecycle replication versioning"
).split()

NEEDLE_MSG_RARE = "anomalieplumebench"
NEEDLE_MSG_COMMON = "sessionplumebench"
NEEDLE_FLD = "objetplumebench"
RATE_MSG_RARE = 1000
RATE_MSG_COMMON = 10
RATE_FLD = 500

V4_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")  # RFC 5737, et RIEN d'autre


def make_ip_pool(rng, want_v4, want_v6):
    """768 adresses IPv4 de documentation au maximum ; le reste en 2001:db8::/32 (RFC 3849)."""
    v4 = [f"{net}{i}" for net in V4_NETS for i in range(1, 255)][:want_v4]
    v6 = []
    for _ in range(want_v6):
        g = [f"{rng.below(0x10000):04x}" for _ in range(6)]
        v6.append("2001:db8:" + ":".join(g))
    return v4 + v6


# Deux réservoirs tirés UNE FOIS à l'initialisation, puis découpés en tranches. Sans eux le
# générateur consommait ~96 tirages de PRNG par événement (un par caractère hexadécimal, un par
# mot) et plafonnait à ~10 k ev/s — trop lent pour 10 M. Les tranches gardent la même distribution
# de longueur et de vocabulaire, et le déterminisme est intact (les réservoirs viennent du même
# PRNG graine).
POOL_TEXT_BYTES = 1 << 20
POOL_HEX_BYTES = 1 << 18


def make_pools_text(rng):
    words, size = [], 0
    while size < POOL_TEXT_BYTES:
        w = VOCAB[rng.below(len(VOCAB))]
        words.append(w)
        size += len(w) + 1
    return " ".join(words)


def make_pool_hex(rng):
    chunks = []
    for _ in range(POOL_HEX_BYTES // 16):
        chunks.append(f"{rng.next():016x}")
    return "".join(chunks)


def text_of_length(rng, n, pool, needles=()):
    """Tranche de longueur n dans le réservoir de texte, recalée sur des frontières de mot ; les
    aiguilles sont préfixées telles quelles pour que la sélectivité soit EXACTEMENT le taux
    annoncé (une aiguille tronquée ne serait plus trouvable et faussererait la sélectivité)."""
    if n <= 0:
        return ""
    head = (" ".join(needles) + " ") if needles else ""
    want = n - len(head)
    if want <= 0:
        return head.strip()
    off = rng.below(len(pool) - want - 32)
    while off < len(pool) and pool[off] != " ":  # démarrer sur un début de mot
        off += 1
    s = pool[off + 1: off + 1 + want]
    cut = s.rfind(" ")  # ne pas laisser un mot tronqué en fin (il ne serait pas indexable)
    return head + (s[:cut] if cut > 0 else s)


def value_of(rng, key, kind, avg_len, card, pools):
    """Valeur synthétique pour une clé étendue : type et longueur mesurés, cardinalité mesurée
    (le tirage se fait dans un pool de taille `card`, donc `dc(clé)` du banc ≈ celle de la prod)."""
    if kind == "integer":
        return rng.below(max(card, 1) * 7 + 1)
    if key in ("src_ip", "rhost", "remote_address", "client_ip"):
        return rng.pick(pools["ip"])
    if key in ("dst_ip",):
        return rng.pick(pools["dst"])
    if key in ("user", "auid", "uid", "owner", "subject", "accessKey"):
        return f"bench-user-{rng.below(max(card, 1)):04d}"
    if key in ("host", "dst_host", "vhost", "unit", "pod", "ns", "namespace", "container", "image"):
        return f"bench-{key}-{rng.below(max(card, 1)):05d}.plume.invalid"
    if key in ("url",):
        return f"https://svc-{rng.below(max(card, 1)):04d}.example.com/{rng.pick(VOCAB)}"
    n = max(int(avg_len or 8), 1)
    idx = rng.below(max(card, 1))
    if n <= 4:  # petites valeurs discrètes (status, code, method, dir…) : énumération
        return f"{idx % max(card, 1):0{n}d}"[:n]
    stem = f"{idx:x}"
    need = max(n - len(stem) - 1, 0)
    hp = pools["hex"]
    off = rng.below(len(hp) - need - 1)
    return (stem + "-" + hp[off:off + need])[:n]


class SourceModel:
    """Un modèle par source : tout ce qui est tiré à l'exécution est précalculé ici, pour que la
    boucle chaude ne fasse que des tirages entiers."""

    def __init__(self, spec):
        self.name = spec["name"]
        self.n = spec["n"]
        sev = {int(k): v for k, v in (spec.get("severity") or {}).items()} or {1: 1}
        self.sev_keys = sorted(sev)
        self.sev_cum, self.sev_tot = cumulative([sev[k] for k in self.sev_keys])
        cats = {k: v for k, v in (spec.get("categories") or {}).items() if k} or {"": 1}
        self.cat_keys = sorted(cats)
        self.cat_cum, self.cat_tot = cumulative([cats[k] for k in self.cat_keys])
        ml = spec.get("msg_len") or {}
        self.msg_min = int(ml.get("min") or 24)
        self.msg_avg = int(ml.get("avg") or 80)
        self.msg_max = int(ml.get("max") or 200)
        self.src_ip_rate = (spec.get("src_ip_present") or 0) / max(spec["n"], 1)
        # clés étendues : (clé, taux de présence, type, longueur moyenne, cardinalité)
        self.fields = []
        for f in spec.get("fields") or []:
            if f["key"] == "cim":
                continue  # posé par le daemon (cim_stamp) — le générateur ne le double pas
            self.fields.append((f["key"], f["n"] / max(spec["n"], 1),
                                f["type"], f.get("avg_len") or 8, f.get("card") or 1))


def build_models(profile):
    models = [SourceModel(s) for s in profile["sources"]["list"]]
    cum, tot = cumulative([m.n for m in models])
    return models, cum, tot


def build_hour_curve(profile):
    h = profile["temporal"]["per_hour_of_day"]
    keys = sorted(int(k) for k in h)
    cum, tot = cumulative([h[str(k)] if str(k) in h else h[k] for k in keys])
    return keys, cum, tot


def generate(profile, count, end_ts, span_days, seed, hosts, batch_events, skip=0):
    """Générateur paresseux : rend des enveloppes prêtes pour POST /api/ingest.

    `skip` PROLONGE un jeu de données existant sans le dupliquer : les `skip` premiers événements
    sont produits puis JETÉS, ce qui avance le PRNG exactement comme lors du premier passage. La
    suite est donc la CONTINUATION du même flux déterministe, avec les mêmes clés `dedup` — et non
    un second jeu à une autre graine, qui aurait un autre profil de cardinalités. Le coût est le
    temps de génération pure des lignes jetées (mesuré : ~18 000 ev/s), jamais de l'ingest."""
    rng = Rng(seed)
    models, mcum, mtot = build_models(profile)
    hkeys, hcum, htot = build_hour_curve(profile)
    bt = profile["bench_target"]
    want_v6 = max(int(bt["src_ip_target_cardinality"]) - 762, 0)
    pools = {"ip": make_ip_pool(rng, 762, want_v6),
             "dst": make_ip_pool(rng, 25, 0),
             "hex": make_pool_hex(rng)}
    text_pool = make_pools_text(rng)
    hostnames = [f"bench-node-{i:03d}.plume.invalid" for i in range(hosts)]
    span = span_days * 86400
    start = end_ts - span

    batch, made = [], 0
    total = count + skip
    while made < total:
        made += 1
        # --- horodatage : jour uniforme sur la fenêtre, heure selon la courbe MESURÉE
        day = rng.below(span_days)
        hour = rng.weighted(hkeys, hcum, htot)
        ts = start + day * 86400 + hour * 3600 + rng.below(3600)
        m = rng.weighted(models, mcum, mtot)
        sev = rng.weighted(m.sev_keys, m.sev_cum, m.sev_tot)
        cat = rng.weighted(m.cat_keys, m.cat_cum, m.cat_tot)
        host = rng.pick(hostnames)

        # --- longueur du message : triangulaire min/avg/max (l'histogramme mesuré est unimodal
        #     par source ; on ne prétend pas reproduire sa forme exacte, seulement ses bornes)
        if m.msg_max > m.msg_min:
            a = rng.frac() + rng.frac()
            mlen = int(m.msg_min + (m.msg_avg - m.msg_min) * a) if a <= 1 else \
                int(m.msg_avg + (m.msg_max - m.msg_avg) * (a - 1))
        else:
            mlen = m.msg_min
        needles = []
        if made % RATE_MSG_RARE == 0:
            needles.append(NEEDLE_MSG_RARE)
        if made % RATE_MSG_COMMON == 0:
            needles.append(NEEDLE_MSG_COMMON)
        msg = text_of_length(rng, mlen, text_pool, needles)

        fields = {}
        for key, rate, kind, avg_len, card in m.fields:
            if rate >= 1.0 or rng.frac() < rate:
                fields[key] = value_of(rng, key, kind, avg_len, card, pools)
        if made % RATE_FLD == 0:
            fields["needle"] = NEEDLE_FLD

        ev = {"ts": ts, "source": m.name, "category": cat, "severity": sev,
              "host": host, "message": msg, "fields": fields,
              # dedup unique -> rejeu idempotent (INSERT OR IGNORE). Écart connu avec la prod
              # (62 % de NULL là-bas) : l'index UNIQUE est donc PLUS gros ici.
              "dedup": f"b{seed:x}-{made:09d}"}
        if fields.get("src_ip"):
            ev["src_ip"] = fields["src_ip"]
        elif rng.frac() < m.src_ip_rate:
            ev["src_ip"] = rng.pick(pools["ip"])
        if fields.get("dst_ip"):
            ev["dst_ip"] = fields["dst_ip"]
        if fields.get("url"):
            ev["url"] = fields["url"]

        if made <= skip:
            continue          # avance le PRNG à l'identique, ne rend rien
        batch.append(ev)
        if len(batch) >= batch_events:
            yield {"ts": batch[-1]["ts"], "host": batch[-1]["host"],
                   "kind": "events", "events": batch}
            batch = []
    if batch:
        yield {"ts": batch[-1]["ts"], "host": batch[-1]["host"],
               "kind": "events", "events": batch}


def post_batch(url, token, body, retries=6):
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Length": str(len(body)),
    })
    delay = 0.5
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < retries - 1:
                time.sleep(delay)
                delay = min(delay * 2, 8)
                continue
            sys.exit(f"POST {url} -> HTTP {e.code}: {e.read()[:400]!r}")
        except OSError as e:
            if attempt < retries - 1:
                time.sleep(delay)
                delay = min(delay * 2, 8)
                continue
            sys.exit(f"POST {url} injoignable: {e}")
    return 0


def spool_pending(spool_dir):
    try:
        return sum(1 for n in os.listdir(spool_dir) if n.startswith("ingest-"))
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=os.path.join(os.path.dirname(__file__), "profile-prod.json"))
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--skip", type=int, default=0,
                    help="prolonge un jeu existant : jette les N premiers événements du MÊME flux "
                         "déterministe (mêmes dedup) au lieu de changer de graine")
    ap.add_argument("--end-ts", type=int, required=True,
                    help="horodatage du DERNIER événement (epoch s). Le générateur n'appelle "
                         "JAMAIS l'horloge : c'est ce paramètre qui fixe la fenêtre.")
    ap.add_argument("--span-days", type=int, default=None, help="défaut : bench_target.span_days")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0x504C554D45)
    ap.add_argument("--hosts", type=int, default=None, help="défaut : bench_target.hosts")
    ap.add_argument("--batch-events", type=int, default=12000,
                    help="12 000 x ~500 o ≈ 6 Mio, sous le plafond de corps de 8 Mio d'axum")
    ap.add_argument("--post", help="URL /api/ingest — LE VRAI CHEMIN")
    ap.add_argument("--token", help="jeton agent (plume-daemon token <nom>)")
    ap.add_argument("--out-dir", help="écrit les enveloppes en fichiers au lieu de POSTer")
    ap.add_argument("--digest", action="store_true", help="imprime le SHA-256 du flux et sort")
    ap.add_argument("--manifest", help="écrit le manifeste (aiguilles, taux, bornes) en JSON")
    ap.add_argument("--spool-dir", help="régule le débit sur la profondeur du spool du daemon")
    ap.add_argument("--max-spool-files", type=int, default=24)
    ap.add_argument("--progress-every", type=int, default=50)
    a = ap.parse_args()

    with open(a.profile, encoding="utf-8") as fh:
        profile = json.load(fh)
    bt = profile["bench_target"]
    span_days = a.span_days if a.span_days is not None else int(bt["span_days"])
    hosts = a.hosts if a.hosts is not None else int(bt["hosts"])

    if a.manifest:
        man = {
            "generator": "bench/gen_events.py",
            "profile_measured_at": profile["provenance_source"]["measured_at"],
            "params": {"count": a.count, "skip": a.skip, "end_ts": a.end_ts,
                       "span_days": span_days, "seed": hex(a.seed), "hosts": hosts,
                       "batch_events": a.batch_events},
            "window": {"start_ts": a.end_ts - span_days * 86400, "end_ts": a.end_ts},
            "needles": {
                "message_rare": {"token": NEEDLE_MSG_RARE, "one_in": RATE_MSG_RARE,
                                 "expected_rows": a.count // RATE_MSG_RARE},
                "message_common": {"token": NEEDLE_MSG_COMMON, "one_in": RATE_MSG_COMMON,
                                   "expected_rows": a.count // RATE_MSG_COMMON},
                "extended_field": {"key": "needle", "token": NEEDLE_FLD, "one_in": RATE_FLD,
                                   "expected_rows": a.count // RATE_FLD},
            },
            "ip_ranges": {"v4": list(V4_NETS), "v6": "2001:db8::/32",
                          "note": "RFC 5737 / RFC 3849 uniquement — aucune adresse réelle"},
            "determinism": "splitmix64, graine explicite, aucun appel à l'horloge",
        }
        with open(a.manifest, "w", encoding="utf-8") as fh:
            json.dump(man, fh, ensure_ascii=False, indent=1)
            fh.write("\n")

    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)

    h = sha256()
    n_ev = n_batch = n_bytes = 0
    t0 = time.monotonic()
    for env in generate(profile, a.count, a.end_ts, span_days, a.seed, hosts, a.batch_events, a.skip):
        body = json.dumps(env, separators=(",", ":"), sort_keys=True).encode()
        n_batch += 1
        n_ev += len(env["events"])
        n_bytes += len(body)
        if a.digest:
            h.update(body)
        elif a.out_dir:
            with open(os.path.join(a.out_dir, f"ingest-bench-{n_batch:06d}.json"), "wb") as fh:
                fh.write(body)
        elif a.post:
            if a.spool_dir:
                while spool_pending(a.spool_dir) > a.max_spool_files:
                    time.sleep(0.5)
            post_batch(a.post, a.token or "", body)
        else:
            sys.exit("choisir --post, --out-dir ou --digest")
        if n_batch % a.progress_every == 0 and not a.digest:
            el = time.monotonic() - t0
            print(f"  {n_ev:>10} événements  {n_bytes/2**20:8.1f} Mio  "
                  f"{n_ev/max(el,1e-9):8.0f} ev/s produits  spool={spool_pending(a.spool_dir) if a.spool_dir else '-'}",
                  flush=True)

    el = time.monotonic() - t0
    if a.digest:
        print(f"sha256={h.hexdigest()} events={n_ev} batches={n_batch} bytes={n_bytes}")
    else:
        print(f"terminé: {n_ev} événements, {n_batch} lots, {n_bytes/2**20:.1f} Mio produits "
              f"en {el:.1f}s ({n_ev/max(el,1e-9):.0f} ev/s côté générateur)")


if __name__ == "__main__":
    main()
