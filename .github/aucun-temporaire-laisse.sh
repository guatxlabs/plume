#!/usr/bin/env bash
# P7.1-a — GARDE MESURABLE : une suite de tests ne laisse RIEN derrière elle.
#
# MESURÉ le 2026-08-03 sur `01a5cf0`, avant correction : la suite daemon laissait
# 136 fichiers / 38,4 Mio PAR EXÉCUTION, dont 53 `-wal` + 53 `-shm` ORPHELINS — les
# fixtures effaçaient le chemin qu'elles avaient NOMMÉ, et SQLite en crée deux autres
# à côté que personne n'avait nommés. La correction POSSÈDE le répertoire contenant
# (`daemon/src/tmp_possede.rs`) ; ce script est la garde qui empêche le retour du trou.
#
# ⚠ LA GARDE LIT $TMPDIR, JAMAIS `/tmp` EN DUR. C'est le piège exact qui a failli faire
# conclure « pas de fuite » : mesurer `/tmp` alors qu'on détourne soi-même $TMPDIR
# renvoie zéro quoi qu'il arrive. Le job cold_tier de cette même CI détourne $TMPDIR —
# une garde codée en dur y serait verte en permanence, sans jamais rien vérifier.
#
# Usage : aucun-temporaire-laisse.sh "<nom de la suite>"   (à lancer DANS le step de test,
# pour hériter du même $TMPDIR que la suite qu'on vient de faire tourner).
set -euo pipefail

suite="${1:-suite}"
: "${TMPDIR:=/tmp}"
motif='plume-*'

echo "── garde « aucun temporaire laissé » — ${suite}"
echo "   TMPDIR observé : ${TMPDIR}"

# `-mindepth 1` N'EST PAS UN DETAIL. Sans lui, `find <rep>` rend AUSSI le repertoire
# lui-meme, et le job nomme son TMPDIR avec le prefixe que ce motif cherche : la garde se
# comptait donc elle-meme comme residu, a chaque execution. Le defaut est reste invisible
# tant qu'un echec anterieur empechait d'atteindre cette etape.
#
# ET LE CONTROLE POSITIF CHERCHE SON TEMOIN PAR SON NOM, au lieu de compter les
# correspondances : le comptage le faisait passer grace au meme faux positif, si bien que
# l'instrument se validait avec le defaut qu'il devait justement exclure.
# VALIDER L'INSTRUMENT AVANT DE CROIRE SA SORTIE. Sans contrôle positif, un « 0 » d'une
# sonde cassée (mauvais chemin, mauvais motif, find muet) est indiscernable d'un vrai 0.
temoin="${TMPDIR}/plume-temoin-instrument-$$"
: > "${temoin}"
vus=$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "$(basename "${temoin}")" | wc -l)
rm -f "${temoin}"
if [ "${vus}" -lt 1 ]; then
  echo "::error::sonde CASSÉE : elle ne voit pas son propre témoin dans ${TMPDIR} — le résultat ne veut rien dire"
  exit 1
fi
echo "   contrôle positif : OK (la sonde voit ce qu'elle doit voir)"

# LA MESURE.
restes=$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "${motif}" | wc -l)
if [ "${restes}" -ne 0 ]; then
  octets=$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "${motif}" -printf '%s\n' | awk '{s+=$1} END{print s+0}')
  echo "::error::${suite} : ${restes} temporaire(s) laissé(s) dans \$TMPDIR (${octets} octets) — attendu 0"
  echo "::error::un temporaire de test doit être POSSÉDÉ (daemon/src/tmp_possede.rs) : il naît dans un"
  echo "::error::répertoire à lui, effacé récursivement à la destruction du garde — sidecars compris."
  find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "${motif}" -printf '  %10s  %f\n' | sort -k2 | head -40
  exit 1
fi
echo "   résidu : 0 — ${suite} ne laisse rien derrière elle"
