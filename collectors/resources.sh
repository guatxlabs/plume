#!/bin/sh
# Capteur Plume : ressources/perf/réseau -> table metric (cpu/mem/swap/disque/temp/net).
# ROOT (via plume-resources.service). Lecture seule (/proc, /sys). Rates cpu/net via état précédent.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
PREV="$STATE/resources.prev"

load1=$(cut -d' ' -f1 /proc/loadavg)
mem_pct=$(awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2} END{if(t>0)printf "%.1f",(1-a/t)*100; else print 0}' /proc/meminfo)
swap_pct=$(awk '/^SwapTotal/{t=$2} /^SwapFree/{f=$2} END{if(t>0)printf "%.1f",(1-f/t)*100; else print 0}' /proc/meminfo)
# Slab noyau NON recuperable (Mo) : detecte les fuites slab (kmalloc/skbuff...) que mem_pct masque
# (memoire tenue par le noyau, pas par les apps ; un reboot la rend). Normal ~500-1500 Mo.
mem_slab_mb=$(awk '/^SUnreclaim/{printf "%.0f",$2/1024}' /proc/meminfo)
[ -z "$mem_slab_mb" ] && mem_slab_mb=0
disk_pct=$(df -P / | awk 'END{gsub("%","",$5); print $5+0}')
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
cpu_line=$(awk '/^cpu /{idle=$5+$6; tot=0; for(i=2;i<=NF;i++) tot+=$i; print tot" "idle}' /proc/stat)
net_line=$(awk -F'[: ]+' '/wlan0|eth|enp/{rx+=$3; tx+=$11} END{print (rx+0)" "(tx+0)}' /proc/net/dev)
ctot=$(echo "$cpu_line" | cut -d' ' -f1); cidle=$(echo "$cpu_line" | cut -d' ' -f2)
nrx=$(echo "$net_line" | cut -d' ' -f1); ntx=$(echo "$net_line" | cut -d' ' -f2)

cpu_pct=0; net_rx_bps=0; net_tx_bps=0
if [ -f "$PREV" ]; then
  read -r p_ts p_ctot p_cidle p_rx p_tx < "$PREV" || true
  dt=$((ts - p_ts)); [ "$dt" -le 0 ] && dt=1
  cpu_pct=$(awk "BEGIN{d=$ctot-$p_ctot; i=$cidle-$p_cidle; if(d>0)printf \"%.1f\",(1-i/d)*100; else print 0}")
  # clamp >=0 : au reboot/reset le compteur /proc/net/dev repart à 0 -> delta négatif -> point sous l'axe
  net_rx_bps=$(awk "BEGIN{d=($nrx-$p_rx)/$dt; printf \"%.0f\", (d<0?0:d)}")
  net_tx_bps=$(awk "BEGIN{d=($ntx-$p_tx)/$dt; printf \"%.0f\", (d<0?0:d)}")
fi
printf '%s %s %s %s %s\n' "$ts" "$ctot" "$cidle" "$nrx" "$ntx" > "$PREV"

m(){ printf '{"name":"%s","value":%s}' "$1" "$2"; }
# temp_c : pas de sonde thermique (VM/conteneur = aucun hwmon/thermal_zone) -> temp_c reste 0
# -> on NE l'émet PAS (sinon faux « 0 °C » trompeur). Émis seulement si une vraie sonde existe.
tpart=""; [ "$temp_c" != "0" ] && tpart="$(m temp_c "$temp_c"),"
items="$(m cpu_pct "$cpu_pct"),$(m load1 "$load1"),$(m mem_pct "$mem_pct"),$(m swap_pct "$swap_pct"),$(m disk_root_pct "$disk_pct"),${tpart}$(m net_rx_bps "$net_rx_bps"),$(m net_tx_bps "$net_tx_bps"),$(m mem_slab_mb "$mem_slab_mb")"
spool_write "resources-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[%s]}}' "$ts" "$host" "$items")"
