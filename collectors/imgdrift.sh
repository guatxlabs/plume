#!/bin/sh
# Capteur SOC (PLUGIN) : MAJ d'image disponible = nouveau build pousse pour le MEME tag (digest-drift).
# Via skopeo. Complete vuln.sh (CVE) -> remplit la colonne "Dispo" cote DETECTION (la PWA/ArgoCD pousse).
# Plugin : si skopeo absent -> exit 0. Etat = dernier digest connu par image:tag (1er vu = baseline).
# NB : detecte les tags MUTABLES (latest/rolling). Le "nouveau semver dispo" (tag list) = amelioration future.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v skopeo >/dev/null 2>&1 || plume_unavailable update missing-dependency "skopeo absent : derive d image non verifiable"
SEEN="$STATE_DIR/imgdrift.digests"   # lignes: <image:tag>\t<digest> ; cree par le remplacement
                                     # DIFFERE (S30) — sa lecture tolere deja son absence
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
[ -s "$imgs_f" ] || { rm -f "$imgs_f"; plume_exit_nodata; }

# S30 — les mises a jour du registre de digests sont ACCUMULEES ici et n'y sont appliquees qu'APRES
# publication. Avant, le registre etait reecrit dans la boucle : une coupure avant le `spool_write` de
# fin enterrait la derive pour toujours (le digest etait deja « connu » sans avoir ete signale). Le
# rejeu est absorbe integralement au central — la cle `update-<image>-<digest>` est une identite de
# contenu, pas un seau de temps.
upd=$(mktemp "$STATE_DIR/.imgdrift.upd.XXXXXX")
events=""; ni=0
while IFS= read -r img; do
  [ -z "$img" ] && continue
  ni=$((ni + 1)); [ "$ni" -gt "$MAXI" ] && break
  dig=$(skopeo inspect ${PLUME_SKOPEO_OPTS:-} --format '{{.Digest}}' "docker://$img" 2>/dev/null || true)
  [ -z "$dig" ] && continue
  prev=$(grep -F "$img$TAB" "$SEEN" 2>/dev/null | head -1 | cut -f2)
  if [ -z "$prev" ]; then
    printf '%s\t%s\n' "$img" "$dig" >> "$upd"; continue           # baseline (1er passage) — differee aussi
  fi
  [ "$prev" = "$dig" ] && continue                                 # inchange
  printf '%s\t%s\n' "$img" "$dig" >> "$upd"                        # remplacement MIS EN ATTENTE
  m=$(json_escape "$(printf 'MAJ dispo: nouveau build pour %s (digest change)' "$img")")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"update\",\"category\":\"update\",\"severity\":1,\"message\":\"$m\",\"dedup\":\"update-$img-$dig\"}"
done < "$imgs_f"
rm -f "$imgs_f"

# Registre reconstruit : les images dont le digest a change sont retirees, les nouvelles lignes
# ajoutees. Le fichier obtenu ne remplace `$SEEN` qu'apres publication (cf. `state_stage_file`).
if [ -s "$upd" ]; then
  _led=$(mktemp "$STATE_DIR/.imgdrift.led.XXXXXX")
  _keys=$(mktemp "$STATE_DIR/.imgdrift.keys.XXXXXX")
  awk -F"$TAB" '{ print $1 "\t" }' "$upd" > "$_keys"
  # S36 — LE CODE DE RETOUR EST LU, ET SES DEUX SENS SONT DISTINGUES. `grep` rend 1 quand il ne
  # garde AUCUNE ligne (cas normal : toutes les images du registre sont remplacees) et >=2 sur
  # ERREUR (registre illisible). `|| true` les confondait : sur erreur, le registre reconstruit ne
  # contenait plus que les nouveautes, les digests deja connus etaient oublies, et la derive
  # suivante sur ces images-la repassait en silence pour une simple mise en reference.
  _reg_rc=0
  grep -vF -f "$_keys" "$SEEN" > "$_led" 2>/dev/null || _reg_rc=$?
  rm -f "$_keys"
  if [ "$_reg_rc" -le 1 ]; then
    cat "$upd" >> "$_led"
    state_stage_file "$_led" "$SEEN"
  else
    rm -f "$_led"
    plume_lecture_partielle update source_illisible "registre des digests deja vus illisible : il N'EST PAS reconstruit, les images seront reexaminees au passage suivant"
  fi
fi
rm -f "$upd"
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "imgdrift-$ts.json" "$(emit_event "$events")"
