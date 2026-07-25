#!/bin/sh
# Capteur SOC (PLUGIN) : scan de vulnerabilites des images deployees -> events source=vuln.
# = la "detection KACE" cote SOC (CVE + version corrigee) ; la PWA/ArgoCD pousse le correctif.
# Plugin : si trivy absent -> exit 0. Sans jq (trivy --format template -> TSV). Incremental (etat).
# Images : PLUME_VULN_IMAGES="img:tag ..." sinon auto via crictl (k3s). Lourd -> timer quotidien.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v trivy >/dev/null 2>&1 || exit 0
SEV="${PLUME_VULN_MIN_SEVERITY:-HIGH,CRITICAL}"
MAXI="${PLUME_VULN_MAX_IMAGES:-60}"
MAXE="${PLUME_VULN_MAX_EVENTS:-500}"
SEEN="$STATE_DIR/vuln.seen"; touch "$SEEN"
TAB=$(printf '\t')
# template trivy : 1 ligne TSV par vuln (severite, cve, paquet, installee, corrigee) -> pas de jq
TPL='{{ range . }}{{ range .Vulnerabilities }}{{ .Severity }}{{"\t"}}{{ .VulnerabilityID }}{{"\t"}}{{ .PkgName }}{{"\t"}}{{ .InstalledVersion }}{{"\t"}}{{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}-{{ end }}{{"\n"}}{{ end }}{{ end }}'

# --- liste des images a scanner ---
imgs_f=$(mktemp)
if [ -n "${PLUME_VULN_IMAGES:-}" ]; then
  printf '%s\n' ${PLUME_VULN_IMAGES}
elif command -v crictl >/dev/null 2>&1; then
  crictl images 2>/dev/null | awk 'NR>1 && $1!="" && $1!="<none>" {print $1":"$2}'
elif command -v k3s >/dev/null 2>&1; then
  k3s crictl images 2>/dev/null | awk 'NR>1 && $1!="" && $1!="<none>" {print $1":"$2}'
fi | sort -u > "$imgs_f"
[ -s "$imgs_f" ] || { rm -f "$imgs_f"; exit 0; }

sevmap() { case "$1" in CRITICAL) echo 4 ;; HIGH) echo 3 ;; MEDIUM) echo 2 ;; LOW) echo 1 ;; *) echo 0 ;; esac; }

# --- scan : on agrege "sev cve pkg inst fixed img" dans un fichier (pas de pipe vers la boucle) ---
all=$(mktemp); ni=0
while IFS= read -r img; do
  [ -z "$img" ] && continue
  ni=$((ni + 1)); [ "$ni" -gt "$MAXI" ] && break
  trivy image --quiet --scanners vuln --severity "$SEV" --format template --template "$TPL" ${PLUME_TRIVY_OPTS:-} "$img" 2>/dev/null \
    | awk -v img="$img" -F'\t' 'NF>=5 && $2!="" {print $0 "\t" img}' >> "$all" || true
done < "$imgs_f"
rm -f "$imgs_f"

events=""; ne=0
while IFS="$TAB" read -r sev cve pkg inst fixed img; do
  [ -z "${cve:-}" ] && continue
  key="$img|$cve|$pkg"
  grep -qxF "$key" "$SEEN" 2>/dev/null && continue        # deja signale -> incremental
  printf '%s\n' "$key" >> "$SEEN"
  ne=$((ne + 1)); [ "$ne" -gt "$MAXE" ] && break
  s=$(sevmap "$sev")
  m=$(json_escape "$(printf '%s dans %s %s (corrige: %s) image %s' "$cve" "$pkg" "$inst" "$fixed" "$img")")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"vuln\",\"category\":\"vuln\",\"severity\":$s,\"message\":\"$m\",\"dedup\":\"vuln-$key\"}"
done < "$all"
rm -f "$all"
[ -z "$events" ] && exit 0

spool_write "vuln-$ts.json" "$(emit_event "$events")"
