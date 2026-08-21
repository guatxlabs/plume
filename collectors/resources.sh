#!/bin/sh
# Capteur Plume : ressources/perf/réseau -> table metric (cpu/mem/swap/disque/temp/net).
# ROOT (via plume-resources.service). Lecture seule (/proc, /sys). Rates cpu/net via état précédent.
#
# S33 — UNE MESURE QUI N'A PAS PU ÊTRE PRISE N'EST PAS PUBLIÉE COMME UN ZÉRO.
# Ce capteur alimente QUATRE règles à seuil (mémoire, fuite slab noyau, processeur, occupation du
# disque racine). Publier 0 quand la source n'est pas exploitable ne met pas ces règles en retard : il
# les rend STRUCTURELLEMENT INERTES, et rien ne le dit — le seuil « > 90 % » ne peut plus être franchi
# par une série qui vaut 0. La règle appliquée ici est celle que ce fichier tenait DÉJÀ pour la
# température (« pas de sonde -> on NE l'émet PAS, sinon faux 0 °C trompeur »), étendue aux sept
# autres : la mesure DISPARAÎT de l'enveloppe, et un AVEU nommant la clé et la cause part par le canal
# d'indisponibilité existant (`plume_mesures_avouer`, cf. collectors/lib.sh), sur lequel une règle
# livrée alerte déjà. Ni l'un ni l'autre ne suffit seul : l'absence ne dit pas POURQUOI, et l'aveu seul
# laisserait le zéro en place.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
PREV="$STATE/resources.prev"
# PARAMÉTRÉ SUR SES SOURCES, et c'est ce qui rend ce capteur EXERÇABLE. Une garde de CI lui présente une
# arborescence fabriquée dans un temporaire et obtient le même verdict sur n'importe quelle machine —
# y compris une machine dont `/proc` répond parfaitement, qui est le témoin sans lequel une version
# rendant TOUJOURS « illisible » passerait pour correcte. Les valeurs par défaut sont les vraies.
PROC="${PLUME_PROC_ROOT:-/proc}"
DISK_TARGET="${PLUME_DISK_TARGET:-/}"
MEMINFO="$PROC/meminfo"

# est_decimal <valeur> — une valeur est-elle PUBLIABLE telle quelle dans le JSON de l'enveloppe ?
# Ce n'est pas de la coquetterie : `load1` était lu par un `cut` qui rend la chaîne VIDE sur un
# `/proc/loadavg` présent mais vide, et l'enveloppe devenait `{"name":"load1","value":}` — un JSON
# invalide, donc les HUIT mesures du passage jetées d'un coup, sans que rien ne le compte.
est_decimal() {
  case "${1:-}" in
    ''|.|*[!0-9.]*) return 1 ;;
    *.*.*) return 1 ;;
  esac
  return 0
}

# champ_meminfo <clé> — la valeur en kio de `<clé>:` si elle est là ET numérique, RIEN sinon.
# La distinction porte tout le lot : une clé ABSENTE (noyau qui ne l'expose pas, `/proc` masqué par un
# bac à sable, format changé) n'est PAS la même chose qu'une clé présente valant 0, et c'est en les
# confondant qu'on publiait du calme. Pas d'`exit` dans le programme awk : un `exit` s'y lit comme une
# sortie du CAPTEUR pour la garde de CI qui interdit les sorties non classées.
champ_meminfo() {
  awk -v K="$1:" '$1 == K && $2 ~ /^[0-9]+$/ && !vu { print $2; vu = 1 }' "$MEMINFO" 2>/dev/null || true
}

# --- charge moyenne ---------------------------------------------------------------------------------
load1=$(awk '$1 ~ /^[0-9]+([.][0-9]+)?$/ && !vu { print $1; vu = 1 }' "$PROC/loadavg" 2>/dev/null || true)
if [ -z "$load1" ]; then
  plume_mesure_absente load1 "$(plume_cause_mesure "$PROC/loadavg")" "$PROC/loadavg : aucune charge moyenne numérique en tête de fichier"
fi

# --- mémoire ----------------------------------------------------------------------------------------
mem_total=$(champ_meminfo MemTotal)
mem_avail=$(champ_meminfo MemAvailable)
mem_pct=""
if [ -n "$mem_total" ] && [ -n "$mem_avail" ] && [ "$mem_total" -gt 0 ]; then
  mem_pct=$(awk -v t="$mem_total" -v a="$mem_avail" 'BEGIN{printf "%.1f",(1-a/t)*100}')
else
  plume_mesure_absente mem_pct "$(plume_cause_mesure "$MEMINFO")" "$MEMINFO : MemTotal/MemAvailable absents, non numériques, ou MemTotal nul — la règle « mémoire élevée » ne peut plus lever"
fi

# --- swap -------------------------------------------------------------------------------------------
# UN HÔTE SANS SWAP EST UN VRAI ZÉRO, PAS UNE PANNE DE MESURE : `SwapTotal: 0` est lu, compris, et
# publié comme 0. Ce qui n'est pas publiable, c'est une clé ABSENTE — les deux se lisaient « 0 ».
swap_total=$(champ_meminfo SwapTotal)
swap_free=$(champ_meminfo SwapFree)
swap_pct=""
if [ -n "$swap_total" ] && [ "$swap_total" = 0 ]; then
  swap_pct="0.0"
elif [ -n "$swap_total" ] && [ -n "$swap_free" ]; then
  swap_pct=$(awk -v t="$swap_total" -v f="$swap_free" 'BEGIN{printf "%.1f",(1-f/t)*100}')
else
  plume_mesure_absente swap_pct "$(plume_cause_mesure "$MEMINFO")" "$MEMINFO : SwapTotal/SwapFree absents ou non numériques"
fi

# --- slab noyau NON récupérable (Mo) ----------------------------------------------------------------
# Détecte les fuites slab (kmalloc/skbuff...) que mem_pct masque (mémoire tenue par le noyau, pas par
# les apps ; un reboot la rend). Normal ~500-1500 Mo. `SUnreclaim` n'est PAS exposé par tous les
# noyaux : là où il manque, la mesure valait 0 DÉFINITIVEMENT et la règle « fuite slab > 2,5 Go » ne
# pouvait plus lever d'aucune façon. C'est le cas qu'il fallait cesser de confondre avec « pas de fuite ».
slab_kio=$(champ_meminfo SUnreclaim)
mem_slab_mb=""
if [ -n "$slab_kio" ]; then
  mem_slab_mb=$(awk -v k="$slab_kio" 'BEGIN{printf "%.0f",k/1024}')
else
  plume_mesure_absente mem_slab_mb "$(plume_cause_mesure "$MEMINFO")" "$MEMINFO : SUnreclaim non exposé par ce noyau — la règle « fuite slab » est inerte tant que c'est le cas"
fi

# --- occupation du disque racine --------------------------------------------------------------------
# LE CODE DE RETOUR DE `df` ÉTAIT AVALÉ PAR LE TUBE : `df -P / | awk '…print $5+0'` rend 0 ET SORT 0
# quand `df` échoue, parce que c'est le statut d'`awk` qui remonte. Le tube est donc coupé en deux — la
# lecture d'abord, le décodage ensuite — pour que l'échec soit visible au lieu d'être un pourcentage.
df_sortie=$(df -P "$DISK_TARGET" 2>/dev/null) || df_sortie=""
disk_pct=""
if [ -n "$df_sortie" ]; then
  disk_pct=$(printf '%s\n' "$df_sortie" | awk 'END{gsub("%","",$5); if ($5 ~ /^[0-9]+$/) print $5+0}')
fi
if [ -z "$disk_pct" ]; then
  plume_mesure_absente disk_root_pct "$(plume_cause_mesure "$DISK_TARGET")" "df -P $DISK_TARGET : aucune occupation exploitable — la règle « disque / > 90 % » ne peut plus lever"
fi
# température CPU : on CIBLE le capteur CPU (coretemp/k10temp/x86_pkg_temp), pas le plus chaud
# (le max attrape le WiFi/NVMe, souvent plus chauds que le CPU au repos).
temp_c=0
# 1) hwmon coretemp/k10temp/zenpower/cpu_thermal -> temp1_input (Package / Tctl)
for h in /sys/class/hwmon/hwmon*; do
  case "$(cat "$h/name" 2>/dev/null)" in
    coretemp|k10temp|zenpower|cpu_thermal|cpu-thermal)
      [ -r "$h/temp1_input" ] && { temp_c=$(awk '{printf "%.1f",$1/1000}' "$h/temp1_input"); break; } ;;
  esac
done
# 2) sinon : zone thermique CPU (x86_pkg_temp / cpu-thermal)
if [ "$temp_c" = "0" ]; then
  for z in /sys/class/thermal/thermal_zone*; do
    case "$(cat "$z/type" 2>/dev/null)" in
      x86_pkg_temp|cpu-thermal|cpu_thermal)
        [ -r "$z/temp" ] && { temp_c=$(awk '{printf "%.1f",$1/1000}' "$z/temp"); break; } ;;
    esac
  done
fi
# 3) repli : 1re zone thermique lisible (sous-estime mais jamais WiFi/NVMe)
if [ "$temp_c" = "0" ]; then
  for z in /sys/class/thermal/thermal_zone*/temp; do [ -r "$z" ] && { temp_c=$(awk '{printf "%.1f",$1/1000}' "$z"); break; }; done
fi
# --- compteurs cumulés dont on tire des TAUX ---------------------------------------------------------
# `!vu` plutôt qu'un `exit` dans awk : un `exit` s'y lit comme une sortie du CAPTEUR pour la garde de
# CI qui interdit les sorties non classées.
cpu_line=$(awk '/^cpu /{idle=$5+$6; tot=0; for(i=2;i<=NF;i++) tot+=$i; if (tot > 0 && !vu) { print tot" "idle; vu=1 }}' "$PROC/stat" 2>/dev/null || true)
# TOUTES LES INTERFACES SAUF LA BOUCLE LOCALE. Le motif précédent — `wlan0|eth|enp` — ne matchait AUCUN
# des noms que systemd donne le plus souvent (`ens3` en machine virtuelle, `eno1` en serveur, `wlp3s0`
# en portable, `bond0`, `br0`) : sur ces hôtes le débit valait 0 POUR TOUJOURS, ce qui n'est pas une
# panne transitoire mais un hôte muet par construction. Une liste de noms ne peut pas être tenue à
# jour ; le COMPLÉMENT de `lo`, si. Zéro interface comptée est alors un fait à avouer, pas un débit nul.
net_line=$(awk -F'[: ]+' '$2 != "" && $2 != "lo" && $3 ~ /^[0-9]+$/ && $11 ~ /^[0-9]+$/ { rx += $3; tx += $11; n++ } END { if (n > 0) print rx" "tx }' "$PROC/net/dev" 2>/dev/null || true)

ctot=""; cidle=""
if [ -n "$cpu_line" ]; then
  ctot=${cpu_line%% *}; cidle=${cpu_line##* }
else
  plume_mesure_absente cpu_pct "$(plume_cause_mesure "$PROC/stat")" "$PROC/stat : aucune ligne « cpu » exploitable — la règle « CPU > 90 % » ne peut plus lever"
fi
nrx=""; ntx=""
if [ -n "$net_line" ]; then
  nrx=${net_line%% *}; ntx=${net_line##* }
else
  _det_net="$PROC/net/dev : aucune interface hors boucle locale avec des compteurs numériques"
  plume_mesure_absente net_rx_bps "$(plume_cause_mesure "$PROC/net/dev")" "$_det_net"
  plume_mesure_absente net_tx_bps "$(plume_cause_mesure "$PROC/net/dev")" "$_det_net"
fi

# L'ÉCHANTILLON PRÉCÉDENT EST UNE SOURCE COMME UNE AUTRE. Un taux se calcule par DIFFÉRENCE : sans lui
# il n'y a pas de mesure à publier, et l'ancienne forme publiait 0 — c'est-à-dire « aucune activité » —
# à chaque premier passage et à chaque effacement de l'état. Absent ou corrompu, il s'avoue.
prev_etat=absent
p_ts=""; p_ctot=""; p_cidle=""; p_rx=""; p_tx=""
if [ -f "$PREV" ]; then
  read -r p_ts p_ctot p_cidle p_rx p_tx < "$PREV" 2>/dev/null || true
  if est_decimal "${p_ts:-}"; then prev_etat=lu; else prev_etat=corrompu; fi
fi
if [ "$prev_etat" = absent ]; then
  cause_prev=source_absente
  detail_prev="$PREV : aucun échantillon précédent (premier passage, ou état effacé) — un taux ne se calcule que par différence"
else
  cause_prev=forme_inconnue
  detail_prev="$PREV : échantillon précédent illisible ou non numérique"
fi

cpu_pct=""
if plume_mesure_est_absente cpu_pct; then
  :                                   # le compteur lui-même manque : l'absence est déjà avouée
elif [ "$prev_etat" = lu ] && est_decimal "${p_ctot:-}" && est_decimal "${p_cidle:-}"; then
  # Les compteurs passent par `-v` et non par interpolation : une variable vide y devenait un
  # FRAGMENT DE PROGRAMME (`d=-500`), donc un delta négatif, donc un `print 0` parfaitement calme.
  cpu_pct=$(awk -v t="$ctot" -v pt="$p_ctot" -v i="$cidle" -v pi="$p_cidle" 'BEGIN{d=t-pt; k=i-pi; if(d>0)printf "%.1f",(1-k/d)*100}')
else
  plume_mesure_absente cpu_pct "$cause_prev" "$detail_prev"
fi

net_rx_bps=""; net_tx_bps=""
if plume_mesure_est_absente net_rx_bps; then
  :
elif [ "$prev_etat" = lu ] && est_decimal "${p_rx:-}" && est_decimal "${p_tx:-}"; then
  dt=$((ts - p_ts)); [ "$dt" -le 0 ] && dt=1
  # clamp >=0 : au reboot/reset le compteur /proc/net/dev repart à 0 -> delta négatif -> point sous l'axe
  net_rx_bps=$(awk -v c="$nrx" -v p="$p_rx" -v dt="$dt" 'BEGIN{d=(c-p)/dt; printf "%.0f",(d<0?0:d)}')
  net_tx_bps=$(awk -v c="$ntx" -v p="$p_tx" -v dt="$dt" 'BEGIN{d=(c-p)/dt; printf "%.0f",(d<0?0:d)}')
else
  plume_mesure_absente net_rx_bps "$cause_prev" "$detail_prev"
  plume_mesure_absente net_tx_bps "$cause_prev" "$detail_prev"
fi
# S30 — meme figure que les filigranes d'events, enjeu different : ce repere ancre le CALCUL DE
# DELTA du passage suivant. Ecrit avant la publication, une coupure entre les deux faisait disparaitre
# le point de la serie sans que rien ne le compte. Mis en attente, il n'est ecrit qu'apres.
state_stage "$PREV" "$ts $ctot $cidle $nrx $ntx"

m(){ printf '{"name":"%s","value":%s}' "$1" "$2"; }
# ajoute_mesure <clé> <valeur> — n'écrit la mesure QUE si elle a été établie. Une valeur vide n'est pas
# un zéro : c'est une mesure qui n'existe pas, et le seul traitement honnête est de ne pas l'inventer.
# Le repli avoue à son tour, pour qu'aucune clé ne puisse disparaître sans un mot.
items=""
ajoute_mesure() {
  if est_decimal "${2:-}"; then
    items="$items${items:+,}$(m "$1" "$2")"
  elif ! plume_mesure_est_absente "$1"; then
    plume_mesure_absente "$1" forme_inconnue "valeur établie mais non publiable (vide ou non numérique)"
  fi
}
ajoute_mesure cpu_pct       "$cpu_pct"
ajoute_mesure load1         "$load1"
ajoute_mesure mem_pct       "$mem_pct"
ajoute_mesure swap_pct      "$swap_pct"
ajoute_mesure disk_root_pct "$disk_pct"
# temp_c : pas de sonde thermique (VM/conteneur = aucun hwmon/thermal_zone) -> temp_c reste 0
# -> on NE l'émet PAS (sinon faux « 0 °C » trompeur). Émis seulement si une vraie sonde existe.
# C'EST CETTE RÈGLE-LÀ, déjà tenue ici, que les huit autres mesures appliquent désormais. Elle ne
# s'avoue pas : l'absence de sonde thermique est une propriété de la MACHINE, pas une lecture ratée.
[ "$temp_c" != "0" ] && ajoute_mesure temp_c "$temp_c"
ajoute_mesure net_rx_bps    "$net_rx_bps"
ajoute_mesure net_tx_bps    "$net_tx_bps"
ajoute_mesure mem_slab_mb   "$mem_slab_mb"

if [ -z "$items" ]; then
  # AUCUNE mesure n'a pu être établie : le capteur n'est pas partiellement aveugle, il est incapable.
  # Cas (I) de la partition — il le DIT et sort, sans publier d'enveloppe vide et sans acquitter le
  # repère mis en attente (rien n'a été publié, donc il n'y a rien à acquitter).
  plume_unavailable resources missing-source "aucune mesure d'hôte exploitable : $(plume_mesures_resume)"
fi
plume_mesures_avouer resources
spool_write_then_ack "resources-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[%s]}}' "$ts" "$host" "$items")"
