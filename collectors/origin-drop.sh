#!/bin/sh
# Capteur Plume (PLUGIN) : rend VISIBLES les paquets rejetes par votre pare-feu d'origine.
# Un pare-feu qui DROP silencieusement ne produit aucun evenement : vous ne savez pas qui frappe le
# service en direct, en contournant votre CDN ou votre ingress. Le remede est cote pare-feu : placer une
# regle de LOG juste AVANT le DROP, avec un prefixe reconnaissable et un rate-limit (pour ne pas se faire
# inonder). Ce capteur parse ce prefixe (defaut 'ORIGIN-DROP:') dans le journal kernel et en fait des
# evenements source=origin-drop / category=firewall.
#
# A DEFINIR PAR VOUS : la table/chaine, les ports proteges, le prefixe et le rate-limit. Exemple nft :
#   log prefix "ORIGIN-DROP: " flags all limit rate <N>/minute
# Le signal utile est "un contournement a ete tente", pas le volume : un rate-limit bas suffit.
# LECTURE SEULE (journalctl -k).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
MAX="${PLUME_ORIGINDROP_MAX:-300}"
command -v nft >/dev/null 2>&1 || plume_unavailable origin-drop missing-dependency "nft absent"                          # pas de nft -> skip propre
nft list table inet "${PLUME_ORIGINDROP_TABLE:-plume-origin-fw}" >/dev/null 2>&1 || plume_unavailable origin-drop subsystem-absent "table nft ${PLUME_ORIGINDROP_TABLE:-plume-origin-fw} absente : le filtrage origine n est pas pose"   # table absente -> rien a faire
plume_init; umask 027

WM="$STATE_DIR/origin-drop.watermark"
last=$(cat "$WM" 2>/dev/null || echo $((ts - 3600)))
tmpf=$(mktemp)
# S36 — UN TUBE N'A QU'UN CODE DE RETOUR, celui de `grep`, pour qui « aucune ligne » vaut 1 : le cas
# NORMAL. L'echec de `journalctl` etait donc invisible, et le filigrane avancait jusqu'a `$ts` sur
# une lecture qui n'avait rien lu — un acces direct a l'origine pouvait disparaitre sans un mot.
kraw=$(mktemp)
_jrnl_ok=1
journalctl -k --since "@$last" --no-pager -o short-unix > "$kraw" 2>/dev/null || _jrnl_ok=0
grep 'ORIGIN-DROP:' "$kraw" > "$tmpf" 2>/dev/null || true
rm -f "$kraw"
events=""; n=0; seen=" "
while IFS= read -r line; do
  [ -n "$line" ] || continue
  src=$(printf '%s' "$line" | sed -n 's/.*SRC=\([0-9A-Fa-f.:]*\).*/\1/p'); [ -n "$src" ] || continue
  dst=$(printf '%s' "$line"  | sed -n 's/.*DST=\([0-9A-Fa-f.:]*\).*/\1/p')
  dpt=$(printf '%s' "$line"  | sed -n 's/.*DPT=\([0-9]*\).*/\1/p')
  spt=$(printf '%s' "$line"  | sed -n 's/.*SPT=\([0-9]*\).*/\1/p')
  proto=$(printf '%s' "$line"| sed -n 's/.*PROTO=\([A-Za-z0-9]*\).*/\1/p')
  case "$src" in *:*) fam=ipv6 ;; *) fam=ipv4 ;; esac
  key="$src"
  case "$seen" in *" $key "*) continue ;; esac                    # dedup par source dans ce passage (calque portscan)
  seen="$seen$key "
  n=$((n + 1)); [ "$n" -le "$MAX" ] || break
  m="ORIGIN-DROP [$fam] $src -> $host:${dpt:-?}/${proto:-?} (acces direct origine = bypass Cloudflare, DROP)"
  fields="{\"src_ip\":\"$src\",\"dst_ip\":\"${dst:-}\",\"dport\":\"${dpt:-}\",\"sport\":\"${spt:-}\",\"proto\":\"${proto:-}\",\"family\":\"$fam\",\"dir\":\"inbound\",\"action\":\"dropped\",\"detector\":\"nft-origin-fw\"}"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"origin-drop\",\"category\":\"firewall\",\"severity\":2,\"message\":\"$m\",\"src_ip\":\"$src\",\"dst_ip\":\"${dst:-}\",\"dir\":\"inbound\",\"dport\":\"${dpt:-}\",\"dedup\":\"origindrop-$src-$((ts / 60))\",\"fields\":$fields}"
done < "$tmpf"
rm -f "$tmpf"
# S30 — filigrane MIS EN ATTENTE (ecrit apres la publication de l'enveloppe d'events, cf. lib.sh).
# Cle `origindrop-<src>-<seau 1 min>` : le seau est court, donc un rejeu produira souvent un doublon
# VISIBLE plutot qu'une absorption — ce qui reste preferable a la perte muette d'avant.
# S36 — et il n'est mis en attente QUE si le journal a ete lu : sa valeur est l'instant du passage,
# elle ne doit rien a la lecture, donc rien ne l'empechait d'acquitter une fenetre jamais lue. Le
# battement de sante part quand meme — son silence dirait « collecteur mort » la ou il est aveugle.
if [ "$_jrnl_ok" = 1 ]; then
  state_stage "$WM" "$ts"
else
  plume_lecture_partielle origin-drop source_illisible "journal du noyau non lu depuis @$last : le filigrane n'avance pas, la fenetre sera relue au passage suivant. La serie origin_drops_seen n'est PAS publiee ce passage — un 0 y ferait lire « aucun acces direct a l origine » sur une lecture qui n a rien lu"
fi

# DEAD-MAN'S-SWITCH (calque portscan.sh/crowdsec.sh) : battement de SANTE a CHAQUE run MEME a 0 hit ->
# Plume distingue « aucun acces direct (normal, event_based) » de « collecteur origin-drop mort ». PAS de
# dedup (event.dedup est UNIQUE -> un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) ->
# chaque battement S'INSERE -> MAX(ts) avance -> heartbeat vivant.
# S36 — LE BATTEMENT ET LA METRIQUE NE COMPTENT PAS CE QU'ILS N'ONT PAS LU. Le filigrane est tenu
# juste au-dessus, mais la phrase la plus rassurante du capteur — « 0 hit ce passage » — et la serie
# `origin_drops_seen` partaient encore, a 0, quand le journal n'avait pas ete lu : une regle a seuil qui
# consomme cette serie n'est alors pas en retard, elle est INERTE, et un tableau de bord y lit « rien
# a signaler » la ou il n'y a plus aucune mesure. La serie DISPARAIT donc de l'enveloppe (S33), et
# l'aveu deja emis ci-dessus la NOMME — un seul evenement pour un seul fait, sur le canal
# d'indisponibilite ou une regle livree alerte deja. Le battement, lui, part TOUJOURS : son silence
# leverait l'alerte MUET, et un capteur aveugle n'est pas un capteur mort.
if [ "$_jrnl_ok" = 1 ]; then
  events="$events${events:+,}$(heartbeat origin-drop "origin-drop sante: $n hit(s) ce passage" "{\"hits_seen\":$n}")"
else
  events="$events${events:+,}$(heartbeat origin-drop "origin-drop sante: journal du noyau NON LU ce passage — aucun compte de hit (l'absence d acces direct ne peut PAS en etre conclue)" "{}")"
fi
spool_write_then_ack "origin-drop-$ts.json" "$(emit_event "$events")" nl
if [ "$_jrnl_ok" = 1 ]; then
  spool_write "origin-dropm-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[{"name":"origin_drops_seen","value":%s}]}}' "$ts" "$host" "$n")" nl
fi
