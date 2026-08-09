#!/usr/bin/env bash
# bench/fts-compaction/mesurer.sh — L'ARBITRAGE `optimize` CONTRE `merge` BORNÉ, REPRODUCTIBLE (P10.7-b).
#
# CE QU'IL MESURE, ET POURQUOI IL NE PASSE PAS PAR LE DAEMON. Le reste de `bench/` interroge un daemon
# vivant : c'est ce qu'il faut pour une latence de requête. Ici la question porte sur ce que FTS5 fait
# de ses SEGMENTS — une propriété du moteur de stockage, pas du produit. On la mesure donc AU PLUS
# PRÈS : sur l'amalgamation SQLCipher que `libsqlite3-sys` 0.28 vendore et que le daemon LIE, avec les
# MÊMES `-D` que son `build.rs` et les MÊMES PRAGMA que `server::tune`.
#
# POURQUOI PAS SIMPLEMENT UN TEST `cargo`. Deux raisons, toutes deux mesurées :
#   1. le profil `dev` de cargo compile ce C à `-O0` (cc-rs suit `OPT_LEVEL`) — une mesure de DURÉE y
#      serait fausse d'un facteur qu'on ne contrôle pas ;
#   2. la fixture pèse 1,2 à 2,4 millions d'événements : ce n'est pas une suite de tests, c'est un banc.
#   La suite `compactage_fts_tests` (daemon) garde les PROPRIÉTÉS ; ce banc établit les NOMBRES.
#
# CE QU'IL NE PROUVE PAS : rien de ceci ne vient de la base de PRODUCTION. La fixture est fabriquée au
# profil mesuré (`bench/profile-prod.json`, histogramme `message_len_hist`) ; la fidélité constatée le
# 2026-08-09 est de +2,5 % sur `event_fts_data` par document. C'est bon, ce n'est pas la production.
#
# Usage :
#   bench/fts-compaction/mesurer.sh [répertoire-de-travail] [nombre-d-événements]
# Défauts : un répertoire temporaire, 1 200 000 événements (≈ 25 min et ≈ 3 Gio de disque au total).
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
travail="${1:-$(mktemp -d)}"
n="${2:-1200000}"
frac=0.584   # la même proportion que la purge mesurée en production (58,4 %)

# --- L'AMALGAMATION EXACTE QUE LE DAEMON LIE -----------------------------------------------------
# LA VERSION EST DÉRIVÉE DU LOCKFILE, PAS CHERCHÉE AU HASARD. Le registre cargo de cette machine
# contenait DEUX `libsqlite3-sys` (0.28.0 et 0.38.1) : prendre « la dernière trouvée » aurait compilé
# une SQLite que le daemon NE LIE PAS, et le banc n'en aurait rien dit. On lit donc la version que
# `daemon/Cargo.lock` FIXE — le jour où `rusqlite` est bumpé, le banc suit tout seul, ou il s'arrête.
version="$(awk '/^name = "libsqlite3-sys"$/{trouve=1; next} trouve && /^version = /{gsub(/[",]/,"",$3); print $3; exit}' "$racine/daemon/Cargo.lock")"
[ -n "$version" ] || { echo "banc FTS : version de libsqlite3-sys introuvable dans daemon/Cargo.lock — AUCUN chiffre publié." >&2; exit 2; }
src="${CARGO_HOME:-$HOME/.cargo}/registry/src"
src="$(find "$src" -maxdepth 3 -type d -path "*/libsqlite3-sys-$version/sqlcipher" 2>/dev/null | head -1)"
[ -n "$src" ] && [ -f "$src/sqlite3.c" ] || {
    echo "banc FTS : amalgamation SQLCipher de libsqlite3-sys-$version introuvable sous le registre cargo." >&2
    echo "  Lancez d'abord \`cargo build --offline\` dans $racine/daemon (elle est vendorée par libsqlite3-sys)." >&2
    exit 2
}
echo "== libsqlite3-sys $version (dérivé de daemon/Cargo.lock) — amalgamation : $src"

mkdir -p "$travail"
cd "$travail"

# --- LES DRAPEAUX DE `libsqlite3-sys/build.rs`, RECOPIÉS ------------------------------------------
# `bundled-sqlcipher-vendored-openssl` ajoute SQLITE_HAS_CODEC + SQLITE_TEMP_STORE=2 et lie libcrypto.
drapeaux=(
  -DSQLITE_CORE -DSQLITE_DEFAULT_FOREIGN_KEYS=1 -DSQLITE_ENABLE_API_ARMOR
  -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_ENABLE_DBSTAT_VTAB -DSQLITE_ENABLE_FTS3
  -DSQLITE_ENABLE_FTS3_PARENTHESIS -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1
  -DSQLITE_ENABLE_LOAD_EXTENSION=1 -DSQLITE_ENABLE_MEMORY_MANAGEMENT -DSQLITE_ENABLE_RTREE
  -DSQLITE_ENABLE_STAT2 -DSQLITE_ENABLE_STAT4 -DSQLITE_SOUNDEX -DSQLITE_THREADSAFE=1
  -DSQLITE_USE_URI -DHAVE_USLEEP=1 -DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2
)
echo "== compilation (-O2 ; ~45 s)"
cc -O2 -c "$src/sqlite3.c" -o sqlite3.o "${drapeaux[@]}" -w
cc -O2 -o banc_fts "$racine/bench/fts-compaction/banc_fts.c" sqlite3.o -I"$src" -lcrypto -lpthread -lm -ldl

# --- VALIDER L'INSTRUMENT AVANT DE S'EN SERVIR ----------------------------------------------------
# Un banc dont on n'a pas vérifié qu'il est bien la SQLite du produit mesure autre chose et le tait.
echo "== validation de l'instrument"
./banc_fts version | tee version.txt
grep -q 'cipher_version=' version.txt || { echo "banc FTS : ce binaire n'est PAS SQLCipher — AUCUN chiffre publié." >&2; exit 2; }
grep -q 'fts5=OUI'      version.txt || { echo "banc FTS : FTS5 absent — AUCUN chiffre publié." >&2; exit 2; }
grep -q 'dbstat=OUI'    version.txt || { echo "banc FTS : dbstat absent, les octets ne seraient pas mesurables." >&2; exit 2; }

# --- LA FIXTURE, PUIS LA PURGE --------------------------------------------------------------------
echo "== fixture : $n événements au profil de bench/profile-prod.json"
./banc_fts build ref.db "$n" 12345
./banc_fts sizes ref.db
cp ref.db purge.db
echo "== purge de $frac (le DELETE qui fabrique le poids mort)"
./banc_fts del purge.db "$frac"

# --- LES BRAS, CHACUN SUR UNE COPIE OCTET-À-OCTET DU MÊME ÉTAT ------------------------------------
# C'est la condition pour que les nombres soient comparables : un bras qui partirait de l'état laissé
# par le précédent ne mesurerait pas la même chose.
for bras in optimize merge-500 merge-2000 merge-positif; do
    cp purge.db "arme-$bras.db"
done
echo; echo "############ BRAS A — optimize (une rafale) ############"
BANC_SANS_PRESCAN=1 ./banc_fts opt arme-optimize.db
echo; echo "############ BRAS B — merge=-500 (incrémental borné) ############"
BANC_SANS_PRESCAN=1 ./banc_fts merge arme-merge-500.db -500 5000
echo; echo "############ BRAS C — merge=-2000 ############"
BANC_SANS_PRESCAN=1 ./banc_fts merge arme-merge-2000.db -2000 5000
echo; echo "############ BRAS D — merge=+2000 (budget POSITIF : le piège) ############"
BANC_SANS_PRESCAN=1 ./banc_fts merge arme-merge-positif.db 2000 5000

# --- INVARIANCE SÉMANTIQUE : la fusion ne change AUCUN résultat -----------------------------------
echo; echo "############ MATCH sur chaque état — les comptes DOIVENT être égaux ############"
for d in purge.db arme-optimize.db arme-merge-500.db arme-merge-2000.db; do
    printf '%-24s ' "$d"; ./banc_fts check "$d" | grep MATCH
done

# --- INTERRUPTION ---------------------------------------------------------------------------------
echo; echo "############ INTERRUPTION — optimize tué en plein vol ############"
cp purge.db arme-kill-opt.db
./banc_fts killopt arme-kill-opt.db 8000 || true
./banc_fts check arme-kill-opt.db
echo; echo "############ INTERRUPTION — SIGKILL réel pendant une séquence merge ############"
cp purge.db arme-kill-merge.db
timeout -s KILL 5 ./banc_fts merge arme-kill-merge.db -500 5000 >/dev/null 2>&1 || true
./banc_fts check arme-kill-merge.db
echo "-- reprise après le SIGKILL : doit converger au MÊME octet que le bras B --"
BANC_SANS_PRESCAN=1 ./banc_fts merge arme-kill-merge.db -500 5000 | grep -E "MERGE|RENDU"

echo; echo "== travail conservé dans $travail (les bases pèsent quelques Gio : effacez-le)"
