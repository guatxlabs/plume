#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : UFW — couche firewall HOTE distincte de nft/fail2ban/crowdsec
# (longtemps un angle mort : un DROP UFW n'apparaissait NULLE PART -> on ne voyait pas pourquoi un
# accès légitime était bloqué). Émet :
#   (1) les [UFW BLOCK] récents du journal kernel -> events  qui(SRC) / quand(ts) / où(DST:DPT) / comment(PROTO,block)
#   (2) des métriques (règles allow, blocs vus ce passage)
#   (3) un dump 'ufw status numbered' sur l'hôte (pour la vue admin-console via le bridge)
# Mode-aware : skip propre si ufw absent ou inactif. Lecture seule, AUCUNE action.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
DUMP="${PLUME_UFW_DUMP:-/var/lib/plume/ufw-status.txt}"
MAX="${PLUME_UFW_MAX:-300}"
command -v ufw >/dev/null 2>&1 || plume_unavailable ufw missing-dependency "ufw absent"
st=$(ufw status 2>/dev/null) || plume_unavailable ufw subsystem-absent "ufw present mais status illisible (droits insuffisants)"                     # pas root / indispo -> skip
case "$st" in *"Status: active"*) : ;; *) plume_unavailable ufw subsystem-absent "ufw installe mais INACTIF : aucun filtrage a observer sur cet hote" ;; esac   # ufw inactif -> rien à surveiller
plume_init
umask 027

# (3) dump pour l'admin-console (best-effort, ignoré si échec)
if ufw status numbered > "$DUMP.tmp" 2>/dev/null; then mv -f "$DUMP.tmp" "$DUMP"; else rm -f "$DUMP.tmp"; fi

# (1) events depuis les [UFW BLOCK] du journal kernel, depuis le watermark (incrémental, borné)
WM="$STATE_DIR/ufw.watermark"
last=$(cat "$WM" 2>/dev/null || echo $((ts - 3600)))      # 1re fois : 1 h en arrière
tmpf=$(mktemp)
# S36 — UN TUBE N'A QU'UN CODE DE RETOUR, celui de sa DERNIERE commande, et pour `grep` « aucune
# ligne trouvee » vaut 1 : c'est le cas NORMAL d'un pare-feu calme. L'echec de `journalctl` etait
# donc invisible, et le filigrane avancait jusqu'a `$ts` sur une lecture qui n'avait rien lu — la
# fenetre etait perdue en silence. Les deux etages sont separes pour que chaque verdict soit lisible.
kraw=$(mktemp)
_jrnl_ok=1
journalctl -k --since "@$last" --no-pager -o short-unix > "$kraw" 2>/dev/null || _jrnl_ok=0
grep 'UFW BLOCK' "$kraw" > "$tmpf" 2>/dev/null || true
rm -f "$kraw"
events=""; n=0; seen=" "
while IFS= read -r line; do
  [ -n "$line" ] || continue
  src=$(printf '%s' "$line" | sed -n 's/.*SRC=\([0-9A-Fa-f.:]*\).*/\1/p'); [ -n "$src" ] || continue
  dpt=$(printf '%s' "$line" | sed -n 's/.*DPT=\([0-9]*\).*/\1/p')
  proto=$(printf '%s' "$line" | sed -n 's/.*PROTO=\([A-Za-z0-9]*\).*/\1/p')
  dst=$(printf '%s' "$line" | sed -n 's/.*DST=\([0-9A-Fa-f.:]*\).*/\1/p')
  # DIRECTION (cohérent avec conntrack) : IN= seul = ENTRANT (scan/probe distant -> SRC = le distant) ;
  # OUT= seul = SORTANT (nous -> distant -> SRC = nous) ; les deux = routé. Lève l'ambiguïté src/dst.
  ifin=$(printf '%s' "$line" | sed -n 's/.* IN=\([^ ]*\).*/\1/p')
  ifout=$(printf '%s' "$line" | sed -n 's/.* OUT=\([^ ]*\).*/\1/p')
  if [ -n "$ifout" ] && [ -z "$ifin" ]; then dir=outbound; elif [ -n "$ifin" ] && [ -z "$ifout" ]; then dir=inbound; else dir=forward; fi
  key="$src>${dpt:-x}/${proto:-x}"
  case "$seen" in *" $key "*) continue ;; esac             # dédup src->port/proto dans ce passage
  seen="$seen$key "
  n=$((n + 1)); [ "$n" -le "$MAX" ] || break
  m="UFW BLOCK [$dir] $src -> :${dpt:-?}/${proto:-?}"
  fields="{\"src_ip\":\"$src\",\"dst_ip\":\"$dst\",\"dport\":\"${dpt:-}\",\"proto\":\"${proto:-}\",\"dir\":\"$dir\",\"action\":\"blocked\"}"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"ufw\",\"category\":\"firewall\",\"severity\":1,\"message\":\"$m\",\"src_ip\":\"$src\",\"dedup\":\"ufw-$src-${dpt:-x}-$((ts / 3600))\",\"fields\":$fields}"
done < "$tmpf"
rm -f "$tmpf"
# S30 — filigrane MIS EN ATTENTE : il n'est ecrit qu'apres la publication de l'enveloppe d'events.
# Avant, il avancait ici et une coupure perdait les blocs UFW de la tranche. Cle `ufw-<src>-<port>-
# <seau horaire>` -> un rejeu tombant dans le meme seau est absorbe par le central.
# S36 — et il n'est mis en attente QUE si le journal a ete lu. Sa valeur est l'instant du passage :
# elle ne doit rien a la lecture, donc rien ne l'empechait d'acquitter une fenetre jamais lue. Le
# capteur publie tout de meme (son battement de sante ne doit pas disparaitre : son silence leve une
# alerte MUET, qui dirait « collecteur mort » la ou il est vivant et aveugle).
if [ "$_jrnl_ok" = 1 ]; then
  state_stage "$WM" "$ts"
else
  plume_lecture_partielle ufw source_illisible "journal du noyau non lu depuis @$last : le filigrane n'avance pas, la fenetre sera relue au passage suivant. La serie ufw_blocks_seen n'est PAS publiee ce passage — un 0 y ferait lire « aucun paquet bloque » sur une lecture qui n a rien lu ; ufw_rules_allow, qui vient de `ufw status` et non du journal, reste publiee"
fi

# (2) métriques (toujours) + (1) events (battement de santé TOUJOURS présent -> ship inconditionnel)
allow=$(printf '%s\n' "$st" | grep -c ALLOW || true)
# DEAD-MAN'S-SWITCH (calque crowdsec.sh/pod-logs.sh) : battement de SANTÉ à CHAQUE run MÊME quand 0 bloc UFW
# -> Plume distingue « UFW calme (normal) » de « collecteur ufw mort ». PAS de dedup (event.dedup est UNIQUE ->
# un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) -> chaque battement S'INSÈRE -> MAX(ts)
# avance -> heartbeat vivant. Le SILENCE de ce battement (>~25 min) lève l'alerte MUET (collecteur CONTINU
# ufw-health, cf. main.rs). $allow est calculé JUSTE au-dessus -> disponible pour le battement.
# S36 — LE BATTEMENT ET LA METRIQUE NE COMPTENT PAS CE QU'ILS N'ONT PAS LU. Le filigrane est tenu
# juste au-dessus, mais la phrase la plus rassurante du capteur — « 0 bloc vu » — et la serie
# `ufw_blocks_seen` partaient encore, a 0, quand le journal n'avait pas ete lu : une regle a seuil qui
# consomme cette serie n'est alors pas en retard, elle est INERTE, et un tableau de bord y lit « rien
# a signaler » la ou il n'y a plus aucune mesure. La serie DISPARAIT donc de l'enveloppe (S33), et
# l'aveu deja emis ci-dessus la NOMME — un seul evenement pour un seul fait, sur le canal
# d'indisponibilite ou une regle livree alerte deja. Le battement, lui, part TOUJOURS : son silence
# leverait l'alerte MUET, et un capteur aveugle n'est pas un capteur mort.
if [ "$_jrnl_ok" = 1 ]; then
  events="$events${events:+,}$(heartbeat ufw "UFW santé: $n bloc(s) vus, $allow règle(s) allow" "{\"blocks_seen\":$n,\"rules_allow\":$allow}")"
else
  events="$events${events:+,}$(heartbeat ufw "UFW santé: journal du noyau NON LU ce passage — aucun compte de bloc ; $allow règle(s) allow" "{\"rules_allow\":$allow}")"
fi
spool_write_then_ack "ufw-$ts.json" "$(emit_event "$events")" nl
if [ "$_jrnl_ok" = 1 ]; then
  spool_write "ufwm-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[{"name":"ufw_rules_allow","value":%s},{"name":"ufw_blocks_seen","value":%s}]}}' "$ts" "$host" "$allow" "$n")" nl
else
  spool_write "ufwm-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[{"name":"ufw_rules_allow","value":%s}]}}' "$ts" "$host" "$allow")" nl
fi
