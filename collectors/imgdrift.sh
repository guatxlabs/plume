#!/bin/sh
# Capteur SOC (PLUGIN) : MAJ d'image disponible = nouveau build pousse pour le MEME tag (digest-drift).
# Via skopeo. Complete vuln.sh (CVE) -> remplit la colonne "Dispo" cote DETECTION (la PWA/ArgoCD pousse).
# Plugin : si skopeo absent -> exit 0. Etat = dernier digest connu par image:tag (1er vu = baseline).
# NB : detecte les tags MUTABLES (latest/rolling). Le "nouveau semver dispo" (tag list) = amelioration future.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v skopeo >/dev/null 2>&1 || exit 0
SEEN="$STATE_DIR/imgdrift.digests"; touch "$SEEN"   # lignes: <image:tag>\t<digest>
MAXI="${PLUME_IMGDRIFT_MAX_IMAGES:-80}"
TAB=$(printf '\t')

imgs_f=$(mktemp)
if [ -n "${PLUME_IMGDRIFT_IMAGES:-}" ]; then
  printf '%s\n' ${PLUME_IMGDRIFT_IMAGES}
elif command -v crictl >/dev/null 2>&1; then
  crictl images 2>/dev/null | awk 'NR>1 && $1!="" && $1!="<none>" {print $1":"$2}'
elif command -v k3s >/dev/null 2>&1; then
  k3s crictl images 2>/dev/null | awk 'NR>1 && $1!="" && $1!="<none>" {print $1":"$2}'
fi | sort -u | grep -v ':<none>$' > "$imgs_f"
[ -s "$imgs_f" ] || { rm -f "$imgs_f"; exit 0; }

events=""; ni=0
while IFS= read -r img; do
  [ -z "$img" ] && continue
  ni=$((ni + 1)); [ "$ni" -gt "$MAXI" ] && break
  dig=$(skopeo inspect ${PLUME_SKOPEO_OPTS:-} --format '{{.Digest}}' "docker://$img" 2>/dev/null || true)
  [ -z "$dig" ] && continue
  prev=$(grep -F "$img$TAB" "$SEEN" 2>/dev/null | head -1 | cut -f2)
  if [ -z "$prev" ]; then
    printf '%s\t%s\n' "$img" "$dig" >> "$SEEN"; continue          # baseline (1er passage)
  fi
  [ "$prev" = "$dig" ] && continue                                 # inchange
  grep -vF "$img$TAB" "$SEEN" > "$SEEN.tmp" 2>/dev/null || true    # remplace l'ancien digest
  printf '%s\t%s\n' "$img" "$dig" >> "$SEEN.tmp"; mv -f "$SEEN.tmp" "$SEEN"
  m=$(json_escape "$(printf 'MAJ dispo: nouveau build pour %s (digest change)' "$img")")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"update\",\"category\":\"update\",\"severity\":1,\"message\":\"$m\",\"dedup\":\"update-$img-$dig\"}"
done < "$imgs_f"
rm -f "$imgs_f"
[ -z "$events" ] && exit 0

spool_write "imgdrift-$ts.json" "$(emit_event "$events")"
