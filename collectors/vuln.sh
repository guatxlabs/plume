#!/bin/sh
# plume-source: vuln
# plume-emits: fields=agent_name,cve,image,vuln_cvss,vuln_fixed,vuln_package,vuln_package_version,vuln_severity
# Capteur SOC (PLUGIN) : scan de vulnerabilites des images deployees -> events source=vuln.
# = la "detection KACE" cote SOC (CVE + version corrigee) ; la PWA/ArgoCD pousse le correctif.
# Plugin : si trivy absent -> exit 0. Sans jq (trivy --format template -> TSV). Incremental (etat).
# Images : PLUME_VULN_IMAGES="img:tag ..." sinon auto via crictl (k3s). Lourd -> timer quotidien.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v trivy >/dev/null 2>&1 || plume_unavailable vuln missing-dependency "trivy absent : aucun scan de vulnerabilite possible"
SEV="${PLUME_VULN_MIN_SEVERITY:-HIGH,CRITICAL}"
MAXI="${PLUME_VULN_MAX_IMAGES:-60}"
MAXE="${PLUME_VULN_MAX_EVENTS:-500}"
# S30 — plus de `touch` : le registre est cree par l'ajout DIFFERE (apres publication), et sa lecture
# (`state_marker_seen`) tolere son absence. Le creer d'avance n'apporterait qu'un fichier vide.
SEEN="$STATE_DIR/vuln.seen"
TAB=$(printf '\t')
# template trivy : 1 ligne TSV par vuln (severite, cve, paquet, installee, corrigee, cvss) -> pas de jq
# P10.32-p — 6e colonne : le score CVSS v3 de la source `nvd` (`.CVSS` est une table source -> score) ;
# vide quand trivy n'en a pas, remplace par `-` dans le filtre awk (une tabulation est un separateur
# BLANC pour `read` : deux tabulations de suite s'y fondent et decaleraient l'image dans le score).
TPL='{{ range . }}{{ range .Vulnerabilities }}{{ .Severity }}{{"\t"}}{{ .VulnerabilityID }}{{"\t"}}{{ .PkgName }}{{"\t"}}{{ .InstalledVersion }}{{"\t"}}{{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}-{{ end }}{{"\t"}}{{ range $src, $c := .CVSS }}{{ if eq (printf "%s" $src) "nvd" }}{{ if $c.V3Score }}{{ $c.V3Score }}{{ end }}{{ end }}{{ end }}{{"\n"}}{{ end }}{{ end }}'

# --- liste des images a scanner ---
imgs_f=$(mktemp)
if [ -n "${PLUME_VULN_IMAGES:-}" ]; then
  printf '%s\n' ${PLUME_VULN_IMAGES}
elif command -v crictl >/dev/null 2>&1; then
  crictl images 2>/dev/null | awk 'NR>1 && $1!="" && $1!="<none>" {print $1":"$2}'
elif command -v k3s >/dev/null 2>&1; then
  k3s crictl images 2>/dev/null | awk 'NR>1 && $1!="" && $1!="<none>" {print $1":"$2}'
fi | sort -u > "$imgs_f"
[ -s "$imgs_f" ] || { rm -f "$imgs_f"; plume_exit_nodata; }

sevmap() { case "$1" in CRITICAL) echo 4 ;; HIGH) echo 3 ;; MEDIUM) echo 2 ;; LOW) echo 1 ;; *) echo 0 ;; esac; }

# --- scan : on agrege "sev cve pkg inst fixed img" dans un fichier (pas de pipe vers la boucle) ---
all=$(mktemp); ni=0
# S36 — LE VERDICT DU TUBE ETAIT CELUI DE `awk`, qui reussit sur une entree vide : une image que le
# scanner n'a pas pu examiner rendait exactement ce que rend une image SANS vulnerabilite. Le
# registre « deja signale » n'enregistre que ce qui a ete vu, donc rien n'etait acquitte a tort —
# mais un scan qui echoue en boucle se lisait « parc sain », et c'est le meme silence. Le scanner et
# le filtre sont donc separes, et les images non examinees sont NOMMEES.
_scan_ko=""
while IFS= read -r img; do
  [ -z "$img" ] && continue
  ni=$((ni + 1)); [ "$ni" -gt "$MAXI" ] && break
  tv=$(mktemp)
  # shellcheck disable=SC2086  (PLUME_TRIVY_OPTS = liste d'options a eclater ; expansion voulue)
  if trivy image --quiet --scanners vuln --severity "$SEV" --format template --template "$TPL" ${PLUME_TRIVY_OPTS:-} "$img" > "$tv" 2>/dev/null; then
    # colonnes 1 a 6 seulement, une vide devient `-` : la ligne garde six champs avant l'image.
    awk -v img="$img" -F'\t' 'NF>=5 && $2!="" {o=""; for (i = 1; i <= 6; i++) { v = (i <= NF ? $i : ""); if (v == "") v = "-"; o = o v "\t" } print o img}' "$tv" >> "$all"
  else
    _scan_ko="$_scan_ko $img"
  fi
  rm -f "$tv"
done < "$imgs_f"
rm -f "$imgs_f"
[ -n "$_scan_ko" ] && plume_lecture_partielle vuln source_illisible "images NON scannees ce passage (leurs CVE ne sont pas marquees « deja signalees », elles seront reexaminees) :$_scan_ko"

# S36, RANG « DU BRUIT AU LIEU DU SILENCE » — MEME DEFAUT QUE `yara`, MEME REMEDE (cf. lib.sh) :
# un registre « deja signale » present mais non interrogeable fait repartir CHAQUE CVE deja connue,
# jusqu'a `severity 4` pour les CRITICAL. Le lot part quand meme (une CVE reellement nouvelle ne doit
# pas disparaitre avec les doublons), mais il est AVOUE.
if plume_registre_illisible "$SEEN"; then
  plume_lecture_partielle vuln source_refusee \
    "le registre des CVE DEJA SIGNALEES ($SEEN) existe mais n'est pas interrogeable : les CVE de ce lot peuvent avoir deja ete signalees."
fi

events=""; ne=0
while IFS="$TAB" read -r sev cve pkg inst fixed cvss img; do
  [ -z "${cve:-}" ] && continue
  key="$img|$cve|$pkg"
  # S30 — le registre « deja signale » est un ACQUITTEMENT : l'ajout est MIS EN ATTENTE et n'est ecrit
  # qu'apres publication. Avant, une coupure entre l'ajout et le `spool_write` de fin enterrait la CVE
  # pour toujours (elle etait « deja signalee » sans jamais avoir ete emise). `state_marker_seen` lit
  # aussi les lignes en attente, sans quoi la meme CVE serait emise deux fois dans le MEME passage.
  state_marker_seen "$SEEN" "$key" && continue            # deja signale -> incremental
  state_stage_append "$SEEN" "$key"
  ne=$((ne + 1)); [ "$ne" -gt "$MAXE" ] && break
  s=$(sevmap "$sev")
  m=$(json_escape "$(printf '%s dans %s %s (corrige: %s) image %s' "$cve" "$pkg" "$inst" "$fixed" "$img")")
  # P10.32-i — image, identifiant et paquet viennent du registre et du scanner : la cle est echappee.
  d=$(json_escape "vuln-$key")
  # P10.32-p — les MEMES champs, au MEME format, que le normaliseur Wazuh du demon
  # (`ingest/endpoint.rs`, famille vulnerability-detector) : les panneaux semes « Vulnerabilites (CVE
  # endpoint) » groupent par eux. Gravite en minuscules comme lui ; `vuln_fixed` (version corrigee) et
  # `image` sont propres a ce capteur ; `agent_name` = l'hote qui scanne (la colonne `host`), sans quoi
  # « Hotes les plus vulnerables » reste vide. Toute valeur venue de trivy ou du registre est echappee.
  vs=$(printf '%s' "$sev" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
  f="\"agent_name\":\"$(json_escape "$host")\",\"cve\":\"$(json_escape "$cve")\",\"vuln_package\":\"$(json_escape "$pkg")\""
  f="$f,\"vuln_package_version\":\"$(json_escape "$inst")\",\"vuln_severity\":\"$(json_escape "$vs")\",\"image\":\"$(json_escape "$img")\""
  [ "$fixed" != "-" ] && f="$f,\"vuln_fixed\":\"$(json_escape "$fixed")\""
  [ "$cvss" != "-" ] && f="$f,\"vuln_cvss\":\"$(json_escape "$cvss")\""
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"vuln\",\"category\":\"vuln\",\"severity\":$s,\"message\":\"$m\",\"dedup\":\"$d\",\"fields\":{$f}}"
done < "$all"
rm -f "$all"
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "vuln-$ts.json" "$(emit_event "$events")"
