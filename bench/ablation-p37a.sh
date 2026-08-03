#!/usr/bin/env bash
# bench/ablation-p37a.sh — P3.7-a : L'ABLATION, c'est-à-dire le seul juge de l'ATTRIBUTION.
#
# CE QUI EST DÉJÀ ÉTABLI SANS CE SCRIPT (donc ce qu'il n'a PAS à prouver) : le coût des 8 sondes
# dead-man's-switch suit `5 x (lignes de la source depuis le dernier battement)`, mesuré au compteur
# SQLITE_STMTSTATUS_VM_STEP — déterministe, donc insensible à la charge — à deux volumes et sur deux
# implémentations SQLite indépendantes (CLI 3.53 et le SQLCipher embarqué). Et il ne le suit plus
# après le correctif : `sonde_cout_independant_du_volume` / `sonde_cout_la_garde_mord`.
#
# CE QUE CE SCRIPT PROUVE, ET RIEN D'AUTRE : que CE coût-là est bien ce qui faisait plier la LOI DE
# DÉBIT mesurée en P6.1-a (`r ∝ N^-1,11` ; CPU par événement ∝ N^1,01). Un coût O(N) sous le verrou
# d'écriture EXPLIQUE la loi ; il ne PROUVE pas qu'il en est le contributeur dominant. Deux binaires,
# un seul changement entre eux, la même charge : si l'exposant s'aplatit, l'attribution devient un
# fait. S'il ne s'aplatit QUE PARTIELLEMENT, c'est un autre fait — et il faudra nommer le reste.
#
# EXIGE LA MACHINE AU REPOS : contrairement aux VM steps, un débit est un chrono. Le script REFUSE de
# démarrer si une campagne tourne.
#
# USAGE :
#   bench/ablation-p37a.sh <ref-avant> <ref-apres> [nb-événements]
# ex. bench/ablation-p37a.sh 302139b HEAD 3600000
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVANT="${1:?ref git AVANT le correctif}"
APRES="${2:?ref git APRÈS le correctif}"
EVENTS="${3:-3600000}"
BASE="${ABLATION_DIR:-$(cd "$REPO/.." && pwd)/.ablation-p37a}"

occupe="$(pgrep -c -f 'measure.py|campagne-10m' || true)"
if [ "${occupe:-0}" != "0" ]; then
  echo "!!! $occupe processus de campagne tournent — un débit mesuré ici ne voudrait rien dire. STOP."
  exit 1
fi

mkdir -p "$BASE"
exec > >(tee -a "$BASE/ablation.log") 2>&1
echo "=== ABLATION P3.7-a — $(date -Is) — $EVENTS événements par bras ==="
echo "charge au départ : loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"

# Un ARBRE DE TRAVAIL SÉPARÉ par bras : on ne touche PAS à l'arbre courant (aucun checkout sauvage sur
# le dépôt de travail, aucun binaire ambigu). Chaque bras compile SA ref dans SON CARGO_TARGET_DIR —
# c'est la variable que `bench/run.sh` lit pour trouver le binaire (il ne construit pas lui-même).
bras() {
  local ref="$1" nom="$2"
  local wt="$BASE/wt-$nom" tgt="$BASE/target-$nom"
  echo ""
  echo "### BRAS $nom — ref=$ref — $(date -Is)"
  rm -rf "$wt"
  git -C "$REPO" worktree add --detach "$wt" "$ref" >/dev/null || { echo "!!! worktree $nom"; return 1; }
  # MÊMES features que le banc publié (run.sh attend le binaire release à $CARGO_TARGET_DIR/release).
  ( cd "$wt" && CARGO_TARGET_DIR="$tgt" nice -n 10 cargo build --release --locked \
      --features cold_tier --manifest-path daemon/Cargo.toml ) || { echo "!!! build $nom"; return 1; }
  rm -rf "$BASE/$nom"
  CARGO_TARGET_DIR="$tgt" BENCH_DIR="$BASE/$nom" BENCH_EVENTS="$EVENTS" BENCH_PHASES=ingest \
    "$wt/bench/run.sh" || echo "!!! le remplissage du bras $nom a rendu non-zéro (C'EST UN RÉSULTAT)"
  git -C "$REPO" worktree remove --force "$wt" >/dev/null 2>&1
}

bras "$AVANT" avant
bras "$APRES" apres

# L'EXPOSANT, pas le débit moyen. Le débit moyen dépend de la machine ; l'EXPOSANT de `r ∝ N^a` est la
# FORME de la courbe, et c'est elle que le correctif doit déplacer.
python3 - "$BASE/avant/ingest_rate.csv" "$BASE/apres/ingest_rate.csv" <<'EOF'
import csv, math, sys

# `bench/probe.py` n'écrit PAS de colonne « rate » : il échantillonne (t_unix, events) — vérifié dans
# probe.py:COLUMNS le 2026-08-03. Le débit instantané est donc DÉRIVÉ de deux échantillons
# consécutifs. Écrire `ligne["rate"]` aurait rendu un exposant sur une colonne absente, c'est-à-dire
# aucun exposant du tout, avec l'aplomb d'un chiffre.
def points(chemin):
    """(N, r) par paire d'échantillons consécutifs. Rend aussi le nombre de points ÉCARTÉS : les
    écarter en silence est exactement la façon dont une régression ment."""
    bruts, xs, ys, ecartes = [], [], [], 0
    try:
        with open(chemin, encoding="utf-8", newline="") as f:
            for ligne in csv.DictReader(f):
                try:
                    bruts.append((float(ligne["t_unix"]), float(ligne["events"])))
                except (KeyError, TypeError, ValueError):
                    ecartes += 1
    except FileNotFoundError:
        return [], [], 0, f"absent : {chemin}"
    for (t0, n0), (t1, n1) in zip(bruts, bruts[1:]):
        dt, dn = t1 - t0, n1 - n0
        # N = lignes DÉJÀ stockées au début de l'intervalle (c'est de ça que le coût dépend).
        if dt > 0 and dn > 0 and n0 > 0:
            xs.append(math.log(n0)); ys.append(math.log(dn / dt))
        else:
            ecartes += 1
    return xs, ys, ecartes, None

def exposant(chemin):
    xs, ys, ecartes, err = points(chemin)
    if err:
        return None, 0, ecartes, err
    if len(xs) < 3:
        return None, len(xs), ecartes, "moins de 3 points exploitables"
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None, len(xs), ecartes, "tous les points au même volume"
    a = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    # R² : un exposant sans qualité d'ajustement n'est pas une mesure, c'est un nombre.
    sst = sum((y - my) ** 2 for y in ys)
    ssr = sum((y - (my + a * (x - mx))) ** 2 for x, y in zip(xs, ys))
    r2 = (1 - ssr / sst) if sst else float("nan")
    return a, len(xs), ecartes, f"R²={r2:.3f}"

for nom, chemin in (("AVANT", sys.argv[1]), ("APRÈS", sys.argv[2])):
    a, n, e, note = exposant(chemin)
    if a is None:
        print(f"{nom} : PAS D'EXPOSANT ({note} ; points={n}, écartés={e}) — ne rien conclure.")
    else:
        print(f"{nom} : r ∝ N^{a:+.3f}   (points={n}, écartés={e}, {note})")
print("")
print("LECTURE : ~-1,1 = le remplissage est quadratique ; ~0 = le débit ne dépend plus du volume déjà")
print("stocké. Un aplatissement PARTIEL est un RÉSULTAT : il dit qu'il reste un autre contributeur, et")
print("il faut le nommer avant de clore le constat. Un R² bas dit que la loi de puissance n'est pas la")
print("bonne forme — auquel cas l'exposant ne veut rien dire, quel qu'il soit.")
EOF
