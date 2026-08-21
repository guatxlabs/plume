#!/bin/sh
# Capteur Plume (PLUGIN) : images tirees + conteneurs demarres via CRI (crictl) -> events source=containerd.
# Repond a "docker/k3s pulls + lifecycle". Plugin : si crictl absent -> exit 0 (skip).
# Dependance MINIMALE : les IMAGES (= les pulls, signal cle) se lisent en TABLE (sans jq) ;
# le lifecycle des conteneurs est un BONUS active seulement si jq est present.
# Diff vs dernier etat ; 1er run = BASELINE (memorise sans alerter -> pas de flood).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
if command -v crictl >/dev/null 2>&1; then CRICTL="crictl"
elif command -v k3s >/dev/null 2>&1; then CRICTL="k3s crictl"
else plume_unavailable containerd missing-dependency "ni crictl ni k3s sur cet hote : runtime conteneur non interrogeable"; fi
plume_init
IMG_STATE="$STATE_DIR/containerd.images"; CTR_STATE="$STATE_DIR/containerd.ctr"
TAB=$(printf '\t')
events=""

# Lit "<id>\t<message>" depuis $1 et ajoute 1 event par id NOUVEAU (hors baseline). Pas de pipe -> $events persiste.
# S34 — CLE D'IDENTITE : l'id CRI lui-meme. Une image est identifiee par son digest, un conteneur
# par son id de runtime — deux valeurs que le runtime attribue au contenu, pas au passage qui les
# lit. Ni `$ts`, ni le PID n'entrent dans la cle : republier apres coupure reproduit donc la MEME
# cle. Le genre est joint parce que deux registres distincts sont tenus (images / conteneurs). La
# cle ne peut pas confondre deux constats reels : le registre « deja signale » garantit qu'un id
# n'est emis QU'UNE FOIS, donc une cle repetee ne peut designer que le rejeu du meme constat.
process_file() {  # $1=fichier_lignes  $2=fichier_etat  $3=first(0/1)  $4=severite  $5=genre
  while IFS="$TAB" read -r idv msg; do
    [ -z "${idv:-}" ] && continue
    # S30 — le registre des ids deja vus est un ACQUITTEMENT : l'ajout est MIS EN ATTENTE et n'est
    # ecrit qu'apres la publication de fin. Avant, un pull d'image enregistre puis perdu par une
    # coupure n'etait plus jamais signale. Ces events ne portent pas de cle -> rejeu = doublons visibles.
    state_marker_seen "$2" "$idv" && continue
    state_stage_append "$2" "$idv"
    [ "$3" = "1" ] && continue
    [ -z "${msg:-}" ] && continue
    mj=$(json_escape "$msg")
    ddj=",\"dedup\":\"containerd-$5-$(json_escape "$idv")\""
    events="$events${events:+,}{\"ts\":$ts,\"source\":\"containerd\",\"category\":\"container\",\"severity\":$4,\"message\":\"$mj\"$ddj}"
  done < "$1"
}

# S30 — plus de `touch` : les registres sont crees par l'ajout DIFFERE (apres publication), et leur
# lecture tolere leur absence. Les creer d'avance vides ne changeait rien au diff, et l'ecriture d'un
# chemin d'etat avant publication est desormais refusee par la garde.
first_img=0; [ -f "$IMG_STATE" ] || first_img=1
first_ctr=0; [ -f "$CTR_STATE" ] || first_ctr=1

# IMAGES (table, sans jq) : colonnes <repo> <tag> <image-id> <size> ; on saute l'entete.
imgs_f=$(mktemp)
$CRICTL images 2>/dev/null | awk 'NR>1 && $3!="" {print $3 "\t image: " $1 ":" $2}' > "$imgs_f" || true
process_file "$imgs_f" "$IMG_STATE" "$first_img" 1 image
rm -f "$imgs_f"

# CONTENEURS (bonus, seulement si jq) : id + name + pod + image + state
if command -v jq >/dev/null 2>&1; then
  ctrs_f=$(mktemp)
  $CRICTL ps -a -o json 2>/dev/null | jq -r '.containers[]? | [.id, "conteneur: " + (.metadata.name // "?") + " pod=" + (.labels["io.kubernetes.pod.name"] // "-") + " image=" + (.image.image // "?") + " (" + (.state // "?") + ")"] | @tsv' > "$ctrs_f" 2>/dev/null || true
  process_file "$ctrs_f" "$CTR_STATE" "$first_ctr" 1 conteneur
  rm -f "$ctrs_f"
fi

[ -z "$events" ] && plume_exit_nodata
spool_write_then_ack "containerd-$ts.json" "$(emit_event "$events")"
