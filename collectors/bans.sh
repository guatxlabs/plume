#!/bin/sh
# Capteur Plume : agrège les BANS ACTIFS de tous les backends -> events category=ban (cherchables :
#   category:ban ip:1.2.3.4   -> cette IP est-elle bannie, et par quoi ?
#   source:fail2ban category:ban   -> tous les bans fail2ban
# Backends : fail2ban (hôte, fail2ban-client) + CrowdSec (cscli decisions, mode-aware host/k3s).
# ROOT. OPT-IN. Dédup HORAIRE : un ban actif réapparaît chaque heure (récent = courant) ; une IP
# unban cesse de réapparaître -> vieillit via la rétention. cf respond.sh pour l'UNBAN.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
bucket=$((ts / 3600))
events=""
nb=0   # nb de bans actifs EMIS ce run (fail2ban + crowdsec) -> {active_bans} du battement de santé
emit() { # $1=source $2=ip $3=label
  case "$2" in *.*|*:*) : ;; *) return ;; esac    # IPv4/IPv6 seulement
  m=$(json_escape "$(printf 'BAN actif %s (%s)' "$2" "$3" | cut -c1-200)")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"$1\",\"category\":\"ban\",\"severity\":3,\"message\":\"$m\",\"src_ip\":\"$2\",\"dedup\":\"ban-$1-$2-$bucket\",\"fields\":{\"action\":\"ban\"}}"
  nb=$((nb + 1))
}

# =================================================================================================
# S36 — CE CAPTEUR NE SE TAISAIT PAS : IL AFFIRMAIT. C'est ce qui le distingue des autres sites de
# ce lot, et c'est pire. Chaque interrogation de backend etait branchee sur un tube (`| grep | sed |
# tr`) dont le statut est celui du DERNIER maillon : un `fail2ban-client` dont la socket est morte,
# un `cscli` qui ne joint plus sa LAPI, rendaient exactement ce que rend un backend qui n'a AUCUN
# ban — la chaine vide. Le passage n'emettait alors aucun event `category=ban`, et le battement de
# sante partait quand meme en DECLARANT `active_bans: 0` et « 0 ban(s) actif(s) ». Le tableau de bord
# lisait « rien a signaler » a l'instant precis ou plus rien n'etait mesure.
# CE QUE CE ZERO DESARME, nommement : `config.d/rules/catalog/im-ban-storm.json` (severite 2) compte
# `dc(src_ip)` sur `category=ban`. Sans event, la vague de bannissements — le signal « une attaque
# est en cours et les defenses mordent » — ne peut plus etre vue.
# LA FORME EST CELLE QUE `portscan.sh` ET `ufw.sh` TIENNENT DEJA, et elle n'est pas reinventee :
# quand la source n'a pas ete lue, le battement part TOUJOURS (son silence leverait l'alerte MUET),
# mais SANS le compteur et en DISANT que le total ne peut pas en etre conclu ; l'aveu part par le
# canal ou `de-collector-unavailable` alerte deja.
# UN BACKEND ABSENT N'EST PAS UN BACKEND EN PANNE : chaque bloc reste garde par sa detection de
# presence, et seul un backend PRESENT dont une lecture echoue est compte comme non lu. Sans cette
# distinction, tout hote sans CrowdSec avouerait a chaque passage — une garde qui crie toujours
# finit desarmee.
# =================================================================================================
_bans_ko=""     # backends PRESENTS dont une lecture a echoue ce passage

# --- fail2ban (hôte) : chaque jail -> liste des IP bannies ---
if command -v fail2ban-client >/dev/null 2>&1; then
  _f2b_out=$(mktemp "$STATE/.bans.f2b.XXXXXX")
  if fail2ban-client status > "$_f2b_out" 2>/dev/null; then
    jails=$(grep -i "Jail list" "$_f2b_out" | sed 's/.*://' | tr ',' ' ')
    for j in $jails; do
      [ -n "$j" ] || continue
      if fail2ban-client status "$j" > "$_f2b_out" 2>/dev/null; then
        for ip in $(grep -i "Banned IP list" "$_f2b_out" | sed 's/.*Banned IP list:[[:space:]]*//'); do
          emit fail2ban "$ip" "$j"
        done
      else
        _bans_ko="$_bans_ko fail2ban/$j"
      fi
    done
  else
    _bans_ko="$_bans_ko fail2ban"
  fi
  rm -f "$_f2b_out"
fi

# --- fail2ban INTERNE du mailserver (docker-mailserver : jails postfix/dovecot/custom) ---
# Il tourne DANS le pod mail -> INVISIBLE du fail2ban hôte ci-dessus = angle mort (un ban mail
# n'apparaissait nulle part dans le SOC). Mode k3s : exec dans le pod, label "mail/<jail>".
# OPT-IN (PLUME_MAIL_F2B=1) : spécifique à un déploiement type docker-mailserver-en-k3s -> DÉSACTIVÉ
# par défaut (le SOC est générique : on ne suppose ni mailserver, ni k3s). Skip propre si pas de pod.
if [ "${PLUME_MAIL_F2B:-0}" = "1" ]; then
  MNS="${PLUME_MAIL_F2B_NS:-mail}"; MCT="${PLUME_MAIL_F2B_CONTAINER:-mailserver}"; mpod="${PLUME_MAIL_F2B_POD:-}"
  if [ -z "$mpod" ]; then
    if command -v k3s >/dev/null 2>&1; then mpod=$(k3s kubectl -n "$MNS" get pods --no-headers 2>/dev/null | awk '/mailserver/{print $1; exit}')
    elif command -v kubectl >/dev/null 2>&1; then mpod=$(kubectl -n "$MNS" get pods --no-headers 2>/dev/null | awk '/mailserver/{print $1; exit}'); fi
  fi
  if [ -n "$mpod" ]; then
    mkx() { if command -v k3s >/dev/null 2>&1; then k3s kubectl -n "$MNS" exec "$mpod" -c "$MCT" -- "$@"; else kubectl -n "$MNS" exec "$mpod" -c "$MCT" -- "$@"; fi; }
    # Meme correction, meme raison : le pod mail est un backend PRESENT (on vient d'en trouver le pod).
    _mf2b=$(mktemp "$STATE/.bans.mf2b.XXXXXX")
    if mkx fail2ban-client status > "$_mf2b" 2>/dev/null; then
      for mj in $(grep -i "Jail list" "$_mf2b" | sed 's/.*://' | tr ',' ' '); do
        [ -n "$mj" ] || continue
        if mkx fail2ban-client status "$mj" > "$_mf2b" 2>/dev/null; then
          for ip in $(grep -i "Banned IP list" "$_mf2b" | sed 's/.*Banned IP list:[[:space:]]*//'); do
            emit fail2ban "$ip" "mail/$mj"
          done
        else
          _bans_ko="$_bans_ko mail/$mj"
        fi
      done
    else
      _bans_ko="$_bans_ko fail2ban-mail"
    fi
    rm -f "$_mf2b"
  fi
fi

# --- CrowdSec (décisions actives) : mode-aware (PLUME_CSCLI > cscli hôte > k3s exec pod LAPI > kubectl) ---
NS="${PLUME_CROWDSEC_NS:-crowdsec}"; LAPI="${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
# shellcheck disable=SC2086
# CSCLI_PRESENT distingue « aucun backend CrowdSec sur cet hote » (cas nominal, on se tait) de
# « un backend est la et sa lecture a echoue » (on l'avoue). Sans lui, le repli `return 1` ci-dessous
# ferait avouer une indisponibilite sur tout hote qui n'utilise simplement pas CrowdSec.
CSCLI_PRESENT=1
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_cmd() { $PLUME_CSCLI "$@"; }
elif command -v cscli >/dev/null 2>&1; then cscli_cmd() { cscli "$@"; }
elif command -v k3s >/dev/null 2>&1 && k3s kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { k3s kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
elif command -v kubectl >/dev/null 2>&1 && kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
else cscli_cmd() { return 1; }; CSCLI_PRESENT=0; fi
if [ "$CSCLI_PRESENT" -eq 1 ] && command -v jq >/dev/null 2>&1; then
  tmpf=$(mktemp)
  _cs_json=$(mktemp "$STATE/.bans.cs.XXXXXX")
  TAB=$(printf '\t')
  if ! cscli_cmd decisions list -o json > "$_cs_json" 2>/dev/null; then
    _bans_ko="$_bans_ko crowdsec"
  elif ! jq -r '(.[]?|.decisions[]?) | [(.value//"-"),(.scenario//.origin//"crowdsec")] | @tsv' < "$_cs_json" > "$tmpf" 2>/dev/null; then
    # La LAPI a repondu mais sa reponse n'est pas la forme attendue : ce n'est pas « zero decision ».
    _bans_ko="$_bans_ko crowdsec(forme)"
  else
    while IFS="$TAB" read -r ip scen; do [ -n "$ip" ] && emit crowdsec "$ip" "$scen"; done < "$tmpf"
  fi
  rm -f "$tmpf" "$_cs_json"
fi

# DEAD-MAN'S-SWITCH (calque crowdsec.sh/pod-logs.sh) : battement de SANTÉ à CHAQUE run MÊME quand 0 ban actif.
# La liveness de bans.sh est rattachée à source=fail2ban (id COLLECTORS existant) : le dead-man's-switch du
# MOTEUR crowdsec est DÉJÀ porté par crowdsec.sh, on n'en refait pas un ici. PAS de dedup (event.dedup est
# UNIQUE -> un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) -> chaque battement S'INSÈRE
# -> MAX(ts) avance -> heartbeat vivant. Le SILENCE de ce battement (>~25 min) lève l'alerte MUET (collecteur
# CONTINU fail2ban-health, cf. main.rs). On NE coupe PLUS avant (l'ancien « [ -z "$events" ] && exit 0 »
# sautait le battement les runs sans ban) : events porte toujours ce battement -> le spool part toujours.
# S36 — LE COMPTEUR N'EST PUBLIE QUE S'IL A ETE MESURE. `active_bans` est un TOTAL : le publier
# alors qu'un backend present n'a pas repondu en fait un sous-total presente comme un total, et un
# sous-total rassure exactement comme un zero. Quand une lecture a echoue, le battement part quand
# meme — son silence leverait l'alerte MUET du capteur CONTINU, ce qui masquerait le vrai probleme —
# mais SANS le champ, et en le disant. Meme forme que `portscan.sh` et `ufw.sh`.
if [ -n "$_bans_ko" ]; then
  events="$events${events:+,}$(heartbeat fail2ban "bans santé: backend(s) NON LU(S) ce passage —$_bans_ko ; $nb ban(s) vu(s) par les backends lisibles, le total actif ne peut PAS en etre conclu" "{}")"
  plume_lecture_partielle fail2ban source_illisible "backend(s) de bannissement PRESENT(S) mais non lu(s) ce passage :$_bans_ko. Les bans actifs de ces backends ne sont PAS emis, et l'absence de vague de bannissements ne peut PAS en etre conclue."
else
  events="$events${events:+,}$(heartbeat fail2ban "bans santé: $nb ban(s) actif(s)" "{\"active_bans\":$nb}")"
fi
spool_write "bans-$ts.json" "$(emit_event "$events")"
