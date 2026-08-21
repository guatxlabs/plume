#!/usr/bin/env bash
# =============================================================================
# Plume — Authorized-Engagement ENFORCER-EXEMPTION adapter (HOST-SIDE, PULL).
# -----------------------------------------------------------------------------
# SANDBOX INVARIANT : le DAEMON *déclare* (GET /api/engagements/active) ; CET
# adaptateur (privilégié, host-side, modèle PULL) *applique*. Aucune entrée
# réseau sur l'hôte : on tire la liste, on réconcilie, on n'expose rien.
# Le daemon DÉCLARE mais N'EST PAS DE CONFIANCE sur la magnitude : cet
# adaptateur VALIDE tout (CIDR strict + borne de largeur + borne temporelle).
#
# SACRED INVARIANT : l'exemption suspend UNIQUEMENT l'auto-BLOCK des IP scopées.
# Elle NE TOUCHE JAMAIS la détection / la collecte / le logging. Concrètement :
#   - CrowdSec  : une *allowlist* dédiée (les scénarios tournent, la DÉCISION est
#                 supprimée) — jamais on n'édite les décisions/sets managés.
#   - fail2ban  : addignoreip (le filtre voit toujours les lignes ; il ne bannit
#                 pas) — jamais on ne touche aux bans réels.
#   - nft       : une règle 'accept' AU-DESSUS du drop origine (le log
#                 "ORIGIN-DROP:" continue via le collecteur origin-drop).
#
# CONTRAT (réconciliation DÉCLARATIVE, LEVEL-triggered — pas edge) :
#   1. chaque cycle : GET /active -> desired = union des CIDR de scope des
#      engagements actifs, chacun avec son window_end (epoch s).
#   2. VALIDATION STRICTE (allowlist, pas denylist) de chaque CIDR : forme
#      IPv4/IPv6 canonique via python-ipaddress, refus route par défaut /
#      non-spécifiée, borne de LARGEUR (préfixe >= MIN_*_PREFIX), refus de tout
#      caractère hors [0-9a-fA-F.:/] (anti-injection nft / anti-flag cscli-f2b).
#      Le CIDR est CANONISÉ (forme de rendu nft/cscli) et sert de CLÉ partout.
#   3. ADD toute exemption desired manquante ; REMOVE toute exemption
#      adapter-managed dont le CIDR n'est PLUS desired (expiré/terminé =
#      self-heal). Idempotent (ensure-present exact par levier).
#   4. tag DISTINCT par levier (allowlist 'plume-engagement' + description
#      'plume-engagement:<id>' / ignoreip suivi en LEDGER d'ownership /
#      commentaire nft "plume-engagement:<id>|<cidr>") -> l'adaptateur ne touche
#      QUE le sien, JAMAIS les sets/ignoreip managés opérateur.
#   5. WALL-CLOCK : ttl = window_end - now ; window_end BORNÉ (<= now+MAX_WINDOW,
#      défense anti-dérive : on ne fait pas confiance à la magnitude du daemon) ;
#      JAMAIS d'exemption au-delà de window_end même si le daemon la liste
#      encore. TTL natif (cscli -e) RAFRAÎCHI si la fenêtre change (raccourcie
#      OU allongée). Timer dead-man séparé (revert-expired) : nft+f2b n'ont PAS
#      de TTL natif -> ils expirent via ce timer même si CE process meurt/OOM.
#   6. FAIL-CLOSED : si /active échoue (injoignable / non-200) N cycles
#      consécutifs -> REVERT-ALL. Une exemption = une défense BAISSÉE : son mode
#      de panne DOIT être re-arm, jamais laisser-ouvert. (Sens INVERSE de celui
#      du responder face au central : lui, ne rien appliquer laisse les défenses
#      en place ; ici, ne rien faire les laisse BAISSÉES.)
#      État (set appliqué) persisté sur disque -> revert survit aux redémarrages.
#      ET L'ÉTAT D'ARMEMENT SE LIT LUI-MÊME FAIL-CLOSED, sans quoi la phrase
#      ci-dessus est fausse : un compteur d'échecs qu'on ne sait plus lire ne
#      franchit JAMAIS son seuil, et le REVERT-ALL promis ne part jamais. Les
#      trois lectures d'état — compteur d'échecs, battement, set appliqué — ne
#      valent donc PLUS zéro/vide quand elles échouent : elles valent « au
#      seuil » (revert-all), « horloge indécidable » (aucune nouvelle exemption)
#      et « ce qui est tenu n'est pas prouvé » (revert-all + découverte live).
#      Un fichier ABSENT reste, lui, un vrai zéro : c'est le premier cycle.
#   7. Robuste : set -euo pipefail, log journald (tag engagement-adapter),
#      jamais de fuite du token, heartbeat dead-man + garde monotonique horloge.
#
# LIMITE CONNUE (fail2ban) : ignoreip n'a NI TTL natif NI tag -> le self-heal du
# levier f2b dépend du LEDGER d'ownership ($F2BLEDGER, écriture atomique). Si le
# répertoire d'état ENTIER est effacé (pas seulement tronqué), les ignoreip
# adapter deviennent indécouvrables (fail2ban les purge de toute façon à son
# prochain reload/restart). Correctif complet = router f2b via `ignorecommand`
# (chantier), hors de ce patch minimal.
#
# OPT-IN : PLUME_ENGAGEMENT_ADAPTER=1 (sinon exit 0). Réutilise le token agent
# host-bound + le socle mTLS/Host-header + le wrapper cscli k3s-aware de
# respond.sh. Quand PLUME_ENGAGEMENT_MODE=0 côté daemon, /active -> 200 [] (ou
# 404/403 -> fail-closed revert-all) -> desired vide -> NO-OP sûr.
#
# MODE dead-man : `engagement-adapter.sh revert-expired` -> passe LOCALE
# (nft+f2b uniquement, jamais cscli/k3s -> OOM-safe) qui révoque toute exemption
# dont window_end est écoulé, en lisant l'état persisté. Aucune sortie réseau,
# pas de token requis. Lancé par plume-engagement-revert.timer.
# =============================================================================
set -euo pipefail

# ---- gate opt-in (symétrique PLUME_RESPONDER du responder) ------------------
[ "${PLUME_ENGAGEMENT_ADAPTER:-0}" = "1" ] || exit 0

# ---- config (réutilise le socle responder.conf) -----------------------------
SOC="${PLUME_CENTRAL:-}"
HOSTN="${PLUME_HOST_LABEL:-$(hostname)}"
NFAIL="${PLUME_ENGAGEMENT_FAILCLOSED_N:-2}"      # revert-all après N échecs consécutifs
ALLOWNAME="${PLUME_ENGAGEMENT_ALLOWLIST:-plume-engagement}"
STATE_DIR="${PLUME_STATE:-/var/lib/plume/state}"
SPOOL="${PLUME_SPOOL:-/var/lib/plume/spool}"
APPLIED="$STATE_DIR/engagement-adapter.applied"       # set appliqué : cidr<TAB>id<TAB>window_end
F2BLEDGER="$STATE_DIR/engagement-adapter.f2b"          # ownership fail2ban : cidr<TAB>jail (ce QUE l'adaptateur a ajouté)
FAILF="$STATE_DIR/engagement-adapter.failcount"
HEARTBEAT="$STATE_DIR/engagement-adapter.heartbeat"
# nft : table/chaîne du drop origine (plume-origin-fw / prerouting)
NFT_FAM_TBL="${PLUME_ORIGIN_TABLE:-inet plume-origin-fw}"
NFT_CHAIN="${PLUME_ORIGIN_CHAIN:-prerouting}"
# bornes de largeur (anti-supernet) et de temps (anti-window aberrant)
MINV4="${PLUME_ENGAGEMENT_MIN_V4_PREFIX:-24}"    # refuse tout préfixe IPv4 plus LARGE que /24
MINV6="${PLUME_ENGAGEMENT_MIN_V6_PREFIX:-64}"    # refuse tout préfixe IPv6 plus LARGE que /64
MAXW="${PLUME_ENGAGEMENT_MAX_WINDOW:-86400}"     # borne DURE (s) sur window_end - now (miroir du clamp daemon)
SKEW_TOL="${PLUME_ENGAGEMENT_SKEW_TOL:-600}"     # recul d'horloge toléré (s) avant de refuser d'étendre

umask 027
mkdir -p "$STATE_DIR"
touch "$APPLIED" 2>/dev/null || true
NOW="$(date +%s)"

log() { printf '%s engagement-adapter: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }   # -> journald (SyslogIdentifier)

# =============================================================================
# LIRE SON PROPRE ÉTAT D'ARMEMENT — SANS VALEUR PAR DÉFAUT.
# -----------------------------------------------------------------------------
# L'en-tête de ce fichier écrit un invariant FAIL-CLOSED : « une exemption est une
# défense BAISSÉE : son mode de panne DOIT être re-arm, jamais laisser-ouvert ».
# Trois lectures faisaient l'INVERSE de cette phrase, et toujours de la même
# façon : `x="$(cat "$F" 2>/dev/null || echo 0)"`. Le zéro est ici la valeur la
# plus RASSURANTE de chaque série — compteur d'échecs à zéro = rien à ré-armer,
# battement à zéro = aucune horloge suspecte — et une lecture qui échoue la
# rendait telle quelle. Un compteur d'échecs qu'on ne sait plus lire ne franchit
# JAMAIS son seuil : le REVERT-ALL promis ne se déclenchait plus, et les
# exemptions tenaient indéfiniment pendant que le central était injoignable.
#
# VOCABULAIRE FERMÉ DES CAUSES — LES MÊMES MOTS que le démon et que les capteurs.
# Réécrit ici et non emprunté : cet adaptateur est un ENFORCER et ne dépend
# d'AUCUNE bibliothèque (cf. l'en-tête) ; une garde de CI vérifie qu'il n'en
# dépend toujours pas. Quelques lignes de duplication valent mieux qu'une garde
# affaiblie. La cardinalité est bornée par `cause_fermee`.
EA_CAUSES="source_absente source_refusee source_illisible forme_inconnue"
cause_fermee() {   # <cause> -> une cause de l'ensemble FERMÉ, jamais une surface libre
  case " $EA_CAUSES " in
    *" $1 "*) printf '%s' "$1" ;;
    *)        printf 'forme_inconnue' ;;
  esac
}

# etat_source <fichier> — l'état d'une source de fichier, en UN mot : `lisible`, ou
# une cause de l'ensemble fermé. `-r` NE SUFFIT PAS : root le voit vrai sur un mode
# 000, et un RÉPERTOIRE le passe — c'est l'ouverture réelle qui tranche.
etat_source() {
  if [ ! -e "$1" ]; then cause_fermee source_absente
  elif [ ! -r "$1" ]; then cause_fermee source_refusee
  elif ! cat "$1" >/dev/null 2>&1; then cause_fermee source_illisible
  else printf 'lisible'; fi
}

# lecture_compteur <fichier> — un compteur d'ARMEMENT persisté, en TROIS cas et sans
# valeur par défaut : `absent` (jamais écrit — c'est un VRAI zéro, premier cycle),
# `<n>` (lu, entier), `illisible:<cause>` (l'appelant DOIT trancher). PARAMÉTRÉE sur
# son fichier : exerçable contre une arborescence fabriquée, hors de toute machine.
lecture_compteur() {
  local _lc_etat _lc_val
  _lc_etat="$(etat_source "$1")"
  case "$_lc_etat" in
    source_absente) printf 'absent'; return 0 ;;
    lisible) ;;
    *) printf 'illisible:%s' "$_lc_etat"; return 0 ;;
  esac
  _lc_val="$(cat "$1" 2>/dev/null || true)"
  case "$_lc_val" in
    ''|*[!0-9]*) printf 'illisible:%s' "$(cause_fermee forme_inconnue)"; return 0 ;;
  esac
  printf '%s' "$_lc_val"
}

# ÉTAT APPLIQUÉ : la liste de CE QUI DOIT ÊTRE RÉVOQUÉ. Lu UNE fois, ici, et tranché
# à chaque endroit qui s'en sert — un `while ... done < "$APPLIED"` sur un fichier
# non ouvrable interrompait le cycle AVANT la réconciliation, donc laissait les
# exemptions en place : la panne de lecture devenait un laisser-ouvert silencieux.
ETAT_APPLIQUE="$(etat_source "$APPLIED")"

# ---- garde monotonique horloge (anti backward-skew, finding wall-clock) ------
# Une horloge qui RECULE gonfle ttl (window_end - now) ET le TTL natif cscli
# dans le même sens : sur recul suspect, on REFUSE d'ajouter/étendre (fail-safe
# vers le revert) et on laisse les TTL natifs pré-recul tenir. Le fix complet
# (référence de temps 'server_now' dans le payload /active) nécessite le daemon.
SKEW_SUSPECT=0
last_hb=0
etat_hb="$(lecture_compteur "$HEARTBEAT")"
case "$etat_hb" in
  absent)      last_hb=0 ;;                       # premier cycle : aucun passage antérieur, fait RÉEL
  illisible:*) SKEW_SUSPECT=1
               log "FAIL-CLOSED horloge: battement NON LU (${etat_hb#illisible:}) sur $HEARTBEAT -> un recul d'horloge devient INDÉCIDABLE ; aucune nouvelle exemption ni extension ce cycle, expiry/révocation maintenus" ;;
  *)           last_hb="$etat_hb" ;;
esac
if [ "$SKEW_SUSPECT" = 0 ] && [ "$last_hb" -gt 0 ] && [ "$NOW" -lt "$((last_hb - SKEW_TOL))" ]; then
  SKEW_SUSPECT=1
  log "WARN horloge: NOW=$NOW < dernier heartbeat=$last_hb - ${SKEW_TOL}s (recul suspect) -> pas de nouvelle exemption/extension ce cycle (fail-safe); expiry/révocation maintenus"
fi

# ---- socle réseau (Host header + mTLS) — repris de respond.sh ----------------
HH=(); [ -n "${PLUME_HOST_HEADER:-}" ] && HH=(-H "Host: $PLUME_HOST_HEADER")
TLS=()
[ -n "${PLUME_TLS_CACERT:-}" ] && TLS+=(--cacert "$PLUME_TLS_CACERT")
[ -n "${PLUME_TLS_CERT:-}" ]   && TLS+=(--cert "$PLUME_TLS_CERT")
[ -n "${PLUME_TLS_KEY:-}" ]    && TLS+=(--key "$PLUME_TLS_KEY")

# ---- wrapper cscli mode-aware (hôte OU k3s exec pod LAPI) — repris respond.sh -
NS="${PLUME_CROWDSEC_NS:-crowdsec}"; LAPI="${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
if [ -n "${PLUME_CSCLI:-}" ]; then
  cscli_cmd() { $PLUME_CSCLI "$@"; }; CSCLI_OK=1
elif command -v cscli >/dev/null 2>&1; then
  cscli_cmd() { cscli "$@"; }; CSCLI_OK=1
elif command -v k3s >/dev/null 2>&1 && k3s kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then
  cscli_cmd() { k3s kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }; CSCLI_OK=1
elif command -v kubectl >/dev/null 2>&1 && kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then
  cscli_cmd() { kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }; CSCLI_OK=1
else
  cscli_cmd() { return 1; }; CSCLI_OK=0
fi

# =============================================================================
# VALIDATION + CANONISATION (allowlist STRICTE, pas denylist) — un seul gate.
# echo la forme CANONIQUE (clé partout) sur stdout et return 0 si :
#   - forme IPv4/IPv6 (ou CIDR) réellement valide (python-ipaddress),
#   - PAS la route par défaut / adresse non-spécifiée,
#   - assez ÉTROITE (préfixe >= MINV4 / MINV6),
#   - aucun caractère hors [0-9a-fA-F.:/] (bloque espace/;/quote/newline/tiret =>
#     anti-injection nft ET anti-flag cscli/fail2ban-client).
# Sinon return != 0 (REFUS -> rien appliqué : fail-safe). Si python3 absent,
# return != 0 => aucune exemption (fail-CLOSED), jamais un validateur faible.
# =============================================================================
canon_or_reject() {   # cidr -> stdout canon (rc0) | rc!=0 rejet
  local c="$1"
  # 1er gate en shell (défense en profondeur, indépendant de python) : charset + pas de tiret initial
  case "$c" in ''|-*|*[!0-9a-fA-F.:/]*) return 1 ;; esac
  python3 - "$c" "$MINV4" "$MINV6" 2>/dev/null <<'PY'
import sys, ipaddress
c, minv4, minv6 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
if not c or c[0] == '-' or any(ch not in '0123456789abcdefABCDEF.:/' for ch in c):
    sys.exit(1)
try:
    net = ipaddress.ip_network(c, strict=False)   # strict=False tolère les bits hôte -> masqués
except ValueError:
    sys.exit(1)
if net.network_address.is_unspecified:            # 0.0.0.0/* , ::/* , 0.0.0.0 , ::
    sys.exit(1)
if net.version == 4:
    if net.prefixlen < minv4: sys.exit(1)
    print(net.network_address.compressed if net.prefixlen == 32 else net.compressed)
else:
    if net.prefixlen < minv6: sys.exit(1)
    print(net.network_address.compressed if net.prefixlen == 128 else net.compressed)
PY
}
safe_id() {   # engagement_id -> [A-Za-z0-9._-], tronqué (comment nft borné) — jamais réinjectable
  local s; s="$(printf '%s' "$1" | tr -cd 'A-Za-z0-9._-')"; printf '%s' "${s:0:48}"
}
fam_of()  { case "$1" in *:*) echo ip6 ;; *) echo ip ;; esac; }

# =============================================================================
# LEVIER 1 — CrowdSec : allowlist dédiée 'plume-engagement' (JAMAIS les sets managés)
# =============================================================================
cs_ensure_allowlist() {
  [ "$CSCLI_OK" = 1 ] || return 0
  cscli_cmd allowlists inspect "$ALLOWNAME" >/dev/null 2>&1 && return 0
  cscli_cmd allowlists create "$ALLOWNAME" \
    -d "Plume authorized-engagement exemption (adapter-managed; suppress auto-block of scoped IPs; detection untouched)" \
    >/dev/null 2>&1 || true
}
cs_present() {   # cidr -> 0 si présent dans l'allowlist dédiée
  [ "$CSCLI_OK" = 1 ] || return 1
  cscli_cmd allowlists inspect "$ALLOWNAME" -o json 2>/dev/null \
    | jq -e --arg v "$1" '(.items // [])[]? | select(.value==$v)' >/dev/null 2>&1
}
cs_add() {       # cidr id ttl_s  — TTL natif (-e) : borne dure côté CrowdSec
  [ "$CSCLI_OK" = 1 ] || return 0
  cs_present "$1" && return 0
  cscli_cmd allowlists add "$ALLOWNAME" "$1" -e "${3}s" -d "plume-engagement:$2" >/dev/null 2>&1 || true
}
cs_remove() {    # cidr
  [ "$CSCLI_OK" = 1 ] || return 0
  cscli_cmd allowlists remove "$ALLOWNAME" "$1" >/dev/null 2>&1 || true
}
cs_discover() {  # -> CIDR adapter-managed dans l'allowlist
  [ "$CSCLI_OK" = 1 ] || return 0
  local json; json="$(cscli_cmd allowlists inspect "$ALLOWNAME" -o json 2>/dev/null)" || return 0
  if [ "$ALLOWNAME" = "plume-engagement" ]; then
    # allowlist DÉDIÉE (défaut) : tout y est adapter-managed
    printf '%s' "$json" | jq -r '(.items // [])[]?.value // empty' 2>/dev/null || true
  else
    # allowlist potentiellement PARTAGÉE (override opérateur) : ne réclame QUE nos
    # entrées self-taggées (description 'plume-engagement:...') -> jamais réconcilier
    # au loin des entrées opérateur (self-enforcing, pas convention-dépendant).
    printf '%s' "$json" \
      | jq -r '(.items // [])[]? | select(((.description // .comment // "")|tostring)|startswith("plume-engagement:")) | .value // empty' 2>/dev/null || true
  fi
}

# =============================================================================
# LEVIER 2 — fail2ban : addignoreip sur CHAQUE jail enforcing (le filtre voit tout)
# LEDGER d'ownership : ignoreip n'a NI tag NI TTL natif. On persiste (cidr<TAB>jail)
# de CE QUE l'adaptateur a ajouté -> (a) idempotence, (b) NON-DESTRUCTIF (on ne
# retire QUE là où on a ajouté, jamais un ignoreip statique opérateur), (c) retry
# si delignoreip échoue (on garde en ledger jusqu'à confirmation), (d) découverte
# (self-heal) même si $APPLIED est perdu tant que le ledger survit.
# =============================================================================
F2B_OK=0; command -v fail2ban-client >/dev/null 2>&1 && F2B_OK=1
declare -A F2B_LED
f2b_load_ledger() {
  [ -f "$F2BLEDGER" ] || return 0
  local c j
  while IFS=$'\t' read -r c j; do [ -n "$c" ] && [ -n "$j" ] && F2B_LED["$c"$'\t'"$j"]=1; done < "$F2BLEDGER"
}
f2b_save_ledger() {
  local tmp k; tmp="$(mktemp)"
  { set +u; for k in "${!F2B_LED[@]}"; do printf '%s\n' "$k"; done; set -u; } > "$tmp"
  chmod 0640 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$F2BLEDGER"   # écriture ATOMIQUE (rename) -> jamais de fichier tronqué
}
f2b_jails() {    # liste des jails enforcing (Jail list: a, b, c)
  [ "$F2B_OK" = 1 ] || return 0
  fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '
}
f2b_on_jail() {  # cidr jail -> 0 si ce CIDR est ignoré sur CE jail (match EXACT d'un token)
  [ "$F2B_OK" = 1 ] || return 1
  fail2ban-client get "$2" ignoreip 2>/dev/null \
    | grep -oE '[0-9A-Fa-f:.]+(/[0-9]+)?' | grep -Fxq "$1"
}
f2b_add() {      # cidr -> ignore sur les jails où on ne l'a pas déjà (ledger + pré-existence)
  [ "$F2B_OK" = 1 ] || return 0
  local j
  for j in $(f2b_jails); do
    [ -n "$j" ] || continue
    [ -n "${F2B_LED["$1"$'\t'"$j"]:-}" ] && continue        # déjà à nous (idempotent)
    f2b_on_jail "$1" "$j" && continue                        # pré-existant (opérateur) -> ne pas s'approprier ni toucher
    if fail2ban-client set "$j" addignoreip "$1" >/dev/null 2>&1; then
      F2B_LED["$1"$'\t'"$j"]=1                                # ownership enregistré (persisté en fin de cycle)
    fi
  done
}
f2b_remove() {   # cidr -> retire UNIQUEMENT là où l'adaptateur a ajouté (ledger) ; garde si échec (retry)
  [ "$F2B_OK" = 1 ] || return 0
  local key j pfx="$1"$'\t'
  set +u
  for key in "${!F2B_LED[@]}"; do
    case "$key" in "$pfx"*) ;; *) continue ;; esac
    j="${key#*$'\t'}"
    fail2ban-client set "$j" delignoreip "$1" >/dev/null 2>&1 || true
    f2b_on_jail "$1" "$j" || unset 'F2B_LED[$key]'           # confirmé absent -> drop ledger ; sinon garde (retry next cycle)
  done
  set -u
}
f2b_discover() { # -> CIDR distincts présents dans le ledger (self-heal si $APPLIED perdu)
  local key c; declare -A seen=()
  set +u
  for key in "${!F2B_LED[@]}"; do
    c="${key%%$'\t'*}"; [ -n "${seen[$c]:-}" ] || { printf '%s\n' "$c"; seen["$c"]=1; }
  done
  set -u
}

# =============================================================================
# LEVIER 3 — nft : règle 'accept' commentée dans plume-origin-fw (delete par handle)
# Le CIDR est EMBARQUÉ dans le commentaire quoté "plume-engagement:<id>|<cidr>".
# On réconcilie sur le COMMENTAIRE (self-tag + CIDR canonique), JAMAIS sur le
# rendu 'saddr' que nft canonise à sa façon (/32 -> nu, IPv6 compressé) : c'est
# ce qui casse present/discover si on grep saddr. Le commentaire est quoté au
# niveau du lexer nft (sinon le ':' provoque 'syntax error, unexpected colon').
# =============================================================================
nft_avail() { command -v nft >/dev/null 2>&1 && nft list table $NFT_FAM_TBL >/dev/null 2>&1; }
nft_present() {  # canon_cidr -> 0 si une règle adapter accepte déjà ce CIDR (clé = commentaire)
  nft_avail || return 1
  nft list chain $NFT_FAM_TBL "$NFT_CHAIN" 2>/dev/null \
    | grep -F "plume-engagement:" | grep -Fq "|$1\""
}
nft_add() {      # canon_cidr id -> insert en TÊTE (avant le drop) ; commentaire QUOTÉ (colon-safe)
  nft_avail || return 0
  nft_present "$1" && return 0
  local f; f="$(fam_of "$1")"
  # shellcheck disable=SC2086  (NFT_FAM_TBL = 'inet plume-origin-fw', split voulu)
  # $1 est VALIDÉ (charset [0-9a-fA-F.:/]) -> pas d'injection possible ; $2 est safe_id.
  # Le \" force nft à recevoir un commentaire QUOTÉ contenant le ':' (bash retire ses propres guillemets).
  nft insert rule $NFT_FAM_TBL "$NFT_CHAIN" $f saddr "$1" accept comment "\"plume-engagement:$2|$1\"" >/dev/null 2>&1 || true
}
nft_remove() {   # canon_cidr -> delete par handle toute règle adapter pour ce CIDR (match commentaire)
  nft_avail || return 0
  local h
  while read -r h; do
    [ -n "$h" ] || continue
    # shellcheck disable=SC2086
    nft delete rule $NFT_FAM_TBL "$NFT_CHAIN" handle "$h" >/dev/null 2>&1 || true
  done < <(nft -a list chain $NFT_FAM_TBL "$NFT_CHAIN" 2>/dev/null \
             | grep -F "plume-engagement:" | grep -F "|$1\"" \
             | sed -n 's/.*# handle \([0-9]\+\).*/\1/p')
}
nft_discover() { # -> CIDR (canon) des règles adapter, extrait du COMMENTAIRE (self-tag = autorité)
  nft_avail || return 0
  nft list chain $NFT_FAM_TBL "$NFT_CHAIN" 2>/dev/null \
    | grep -F "plume-engagement:" \
    | sed -n 's/.*comment "plume-engagement:[^|]*|\([^"]*\)".*/\1/p' || true
}

# ---- opérations unifiées (les 3 leviers ensemble) ---------------------------
exempt_add()    { cs_add "$1" "$2" "$3"; f2b_add "$1"; nft_add "$1" "$2"; }   # cidr id ttl_s
# révocation : leviers LOCAUX d'abord (nft+f2b, cheap, pas d'OOM), cscli EN DERNIER
# (chemin k3s exec lourd) -> un OOM sur cscli ne laisse pas nft/f2b bloqués.
exempt_remove() { nft_remove "$1"; f2b_remove "$1"; cs_remove "$1"; }         # cidr

# =============================================================================
# MODE DEAD-MAN : `engagement-adapter.sh revert-expired`
# Révoque toute exemption dont window_end est écoulé, LOCALEMENT (nft+f2b), sans
# cscli (OOM-safe) : nft/f2b n'ont pas de TTL natif -> ce timer garantit leur
# expiry à window_end MÊME SI le process principal est mort/OOM/timer stoppé.
# Ne touche pas à $APPLIED (laissé au loop principal). Pas de réseau/token.
# =============================================================================
if [ "${1:-}" = "revert-expired" ]; then
  f2b_load_ledger
  reverted=0
  if [ "$ETAT_APPLIQUE" = lisible ]; then
    while IFS=$'\t' read -r cidr eid wend; do
      [ -n "$cidr" ] || continue
      case "$wend" in ''|*[!0-9]*) wend=0 ;; esac
      if [ "$wend" -le "$NOW" ]; then nft_remove "$cidr"; f2b_remove "$cidr"; reverted=$((reverted + 1)); fi
    done < "$APPLIED"
  else
    # FAIL-CLOSED. Sans cet état, aucune fenêtre n'est connue : on ne peut pas dire
    # laquelle est écoulée. On révoque donc TOUT ce que la découverte live attribue à
    # l'adaptateur (self-tag nft + ledger f2b). Coût si l'engagement est encore actif :
    # UN cycle sans exemption, que la réconciliation déclarative repose d'elle-même dès
    # que /active répond. Coût de l'inverse : une défense baissée sans terme.
    log "FAIL-CLOSED dead-man: état appliqué NON LU ($ETAT_APPLIQUE) sur $APPLIED -> révocation de TOUTE exemption adapter découverte (nft + ledger f2b) ; elle sera reposée au prochain /active si l'engagement est toujours actif"
    while read -r cidr; do
      [ -n "$cidr" ] || continue
      nft_remove "$cidr"; f2b_remove "$cidr"; reverted=$((reverted + 1))
    done < <(nft_discover; f2b_discover)
  fi
  f2b_save_ledger
  [ "$reverted" -gt 0 ] && log "dead-man revert-expired: $reverted exemption(s) expirée(s) révoquée(s) (leviers locaux nft+f2b ; cscli = TTL natif)"
  exit 0
fi

# =============================================================================
# 1) FETCH /api/engagements/active  (token agent host-bound ; jamais loggé)
# =============================================================================
: "${SOC:?PLUME_CENTRAL requis}"
: "${PLUME_TOKEN:?PLUME_TOKEN requis (token agent host-bound)}"
f2b_load_ledger
BODY_TMP="$(mktemp)"; trap 'rm -f "$BODY_TMP"' EXIT
# P5.5-a : le jeton passe par l'ENTRÉE STANDARD (format de config curl), jamais en argument — il y était
# lisible dans /proc/<pid>/cmdline (mesuré 2026-08-02) et recopié dans `_CMDLINE` journald, que Plume
# collecte lui-même. Échappement `\` puis `"` fait sur place : cet adaptateur est un ENFORCER, et une
# garde de CI vérifie qu'il ne dépend PAS de la bibliothèque des capteurs (surface de dépendance
# minimale pour du code privilégié) — on paie deux lignes plutôt que d'affaiblir cette garde.
http="$(printf 'header = "Authorization: Bearer %s"\n' \
          "$(printf '%s' "$PLUME_TOKEN" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
        | curl -K - "${HH[@]}" "${TLS[@]}" -sS --max-time 15 \
          -o "$BODY_TMP" -w '%{http_code}' \
          "$SOC/api/engagements/active" 2>/dev/null)" || http="000"
body="$(cat "$BODY_TMP" 2>/dev/null || true)"

ok=0
if [ "$http" = "200" ] && printf '%s' "$body" | jq -e 'type=="array"' >/dev/null 2>&1; then ok=1; fi

# LA LECTURE QUI ARME LE FAIL-CLOSED. Sans valeur par défaut : un compteur qu'on ne
# sait plus lire est présumé AU SEUIL, jamais à zéro. Le fichier ABSENT, lui, est un
# vrai zéro (premier cycle) et reste le cas nominal.
etat_fails="$(lecture_compteur "$FAILF")"
case "$etat_fails" in
  absent)      fails=0 ;;
  illisible:*) fails="$NFAIL"
               log "FAIL-CLOSED: compteur d'échecs NON LU (${etat_fails#illisible:}) sur $FAILF -> armement présumé ATTEINT. Une exemption est une défense BAISSÉE : son mode de panne est le re-arm, jamais le laisser-ouvert." ;;
  *)           fails="$etat_fails" ;;
esac

# =============================================================================
# 2) DESIRED  (validation stricte + canon + expiry/borne wall-clock) + fail-closed
# =============================================================================
declare -A DESIRED_ID DESIRED_END
MODE=""
refused=0

if [ "$ok" = 1 ]; then
  # Une remise à zéro qui échoue laisse l'armement EN PLACE (fail-safe vers le revert) —
  # elle n'interrompt pas le cycle, et elle se dit.
  if ! printf '%s\n' 0 > "$FAILF" 2>/dev/null; then
    log "WARN: compteur d'échecs non réinitialisé ($FAILF) — l'armement en place tient (fail-safe vers le revert)"
  fi
  MODE="reconcile"
  while IFS=$'\t' read -r cidr eid wend; do
    [ -n "$cidr" ] || continue
    eid="$(safe_id "$eid")"
    if ! canon="$(canon_or_reject "$cidr")"; then
      log "REFUS scope invalide/trop-large/injection: '$cidr' (eng=$eid)"; refused=$((refused + 1)); continue
    fi
    case "$wend" in ''|*[!0-9]*) continue ;; esac
    if [ "$wend" -le "$NOW" ]; then log "wall-clock: window_end écoulé, non appliqué: $canon (eng=$eid)"; continue; fi
    if [ "$wend" -gt "$((NOW + MAXW))" ]; then
      log "wall-clock: window_end aberrant clampé (anti-dérive): $canon eng=$eid wend=$wend -> now+${MAXW}s"; wend="$((NOW + MAXW))"
    fi
    DESIRED_ID["$canon"]="$eid"; DESIRED_END["$canon"]="$wend"
  done < <(printf '%s' "$body" | jq -r '.[]? | . as $e | ($e.scope[]?) | [ ., ($e.engagement_id//""), (($e.window_end//0)|tostring) ] | @tsv' 2>/dev/null || true)
else
  fails=$((fails + 1))
  if ! printf '%s\n' "$fails" > "$FAILF" 2>/dev/null; then
    log "WARN: compteur d'échecs non persisté ($FAILF) — le cycle suivant le relira comme NON LU, donc ARMÉ (fail-closed)"
  fi
  if [ "$fails" -ge "$NFAIL" ]; then
    MODE="revert-all"   # DESIRED reste vide -> tout le set appliqué sera révoqué
    log "FAIL-CLOSED: /active KO (http=$http) x$fails >= $NFAIL -> REVERT-ALL (re-arme les défenses)"
  else
    if [ "$ETAT_APPLIQUE" = lisible ]; then
      MODE="hold"       # tolère un blip : garde le set, mais applique quand même l'expiry/borne wall-clock
      log "WARN: /active KO (http=$http) x$fails < $NFAIL -> HOLD (expiry-only, exemptions conservées)"
      while IFS=$'\t' read -r cidr eid wend; do
        [ -n "$cidr" ] || continue
        case "$wend" in ''|*[!0-9]*) continue ;; esac
        [ "$wend" -gt "$((NOW + MAXW))" ] && wend="$((NOW + MAXW))"
        [ "$wend" -gt "$NOW" ] && { DESIRED_ID["$cidr"]="$eid"; DESIRED_END["$cidr"]="$wend"; }
      done < "$APPLIED"
    else
      # TENIR un set qu'on ne peut pas LIRE, c'est le tenir sur la foi de rien. DESIRED reste
      # vide -> revert-all, et la découverte live dit quoi révoquer.
      MODE="revert-all"
      log "FAIL-CLOSED: /active KO (http=$http) ET état appliqué NON LU ($ETAT_APPLIQUE) sur $APPLIED -> HOLD impossible -> REVERT-ALL"
    fi
  fi
fi

# =============================================================================
# APPLIED = union(état persisté, découverte live nft+cscli+ledger-f2b) -> self-heal
# revert même si $APPLIED est perdu/corrompu (nft/cscli self-tag ; f2b via ledger).
# APPLIED_END (col3) sert au rafraîchissement du TTL natif cscli sur changement
# de fenêtre (raccourcie OU allongée).
# =============================================================================
declare -A APPLIED_ID APPLIED_END
if [ "$ETAT_APPLIQUE" = lisible ]; then
  while IFS=$'\t' read -r cidr eid wend; do
    [ -n "$cidr" ] || continue
    APPLIED_ID["$cidr"]="$eid"
    case "$wend" in ''|*[!0-9]*) : ;; *) APPLIED_END["$cidr"]="$wend" ;; esac
  done < "$APPLIED"
else
  log "état appliqué NON LU ($ETAT_APPLIQUE) sur $APPLIED -> la réconciliation se rabat sur la DÉCOUVERTE live (nft self-tag + cscli + ledger f2b) ; rien n'est tenu sur la foi d'un fichier non lu"
fi
while read -r cidr; do [ -n "$cidr" ] && : "${APPLIED_ID[$cidr]:=?}"; done < <(nft_discover)
while read -r cidr; do [ -n "$cidr" ] && : "${APPLIED_ID[$cidr]:=?}"; done < <(cs_discover)
while read -r cidr; do [ -n "$cidr" ] && : "${APPLIED_ID[$cidr]:=?}"; done < <(f2b_discover)

# Longueurs sûres sous set -u : un tableau ASSOCIATIF déclaré-jamais-assigné est
# « unbound » pour ${#a[@]}/${!a[@]} (cas revert-all / no-op mode-off) -> compteurs
# derrière set +u, puis n'itérer ${!a[@]} que si le compteur > 0.
set +u; DESIRED_N="${#DESIRED_ID[@]}"; APPLIED_N="${#APPLIED_ID[@]}"; set -u

# =============================================================================
# 3) RECONCILE DÉCLARATIF (level-triggered, idempotent)
# =============================================================================
[ "$DESIRED_N" -gt 0 ] && [ "$SKEW_SUSPECT" = 0 ] && cs_ensure_allowlist

ensured=0; nft_fail=0
if [ "$DESIRED_N" -gt 0 ] && [ "$SKEW_SUSPECT" = 0 ]; then
  for cidr in "${!DESIRED_ID[@]}"; do
    eid="${DESIRED_ID[$cidr]}"; wend="${DESIRED_END[$cidr]}"; ttl=$((wend - NOW))
    [ "$ttl" -gt 0 ] || continue                     # garde-fou wall-clock (double)
    # rafraîchit le TTL natif cscli si la fenêtre a CHANGÉ (raccourcie OU allongée) :
    # la borne dure côté CrowdSec doit suivre window_end, sinon elle est figée à la 1re pose.
    prev="${APPLIED_END[$cidr]:-}"
    if [ -n "$prev" ] && [ "$prev" != "$wend" ]; then cs_remove "$cidr"; fi
    exempt_add "$cidr" "$eid" "$ttl"                  # idempotent (ensure-present exact par levier)
    ensured=$((ensured + 1))
    # anti-silence : le levier nft est censé s'appliquer -> vérifie la présence réelle
    # (aurait attrapé le bug 'colon' : insert avalé par || true, faussement 'appliqué').
    if nft_avail && ! nft_present "$cidr"; then log "WARN levier nft NON appliqué pour $cidr (eng=$eid) — règle absente après insert"; nft_fail=$((nft_fail + 1)); fi
  done
elif [ "$DESIRED_N" -gt 0 ] && [ "$SKEW_SUSPECT" = 1 ]; then
  log "SKIP adds: recul d'horloge suspect (${DESIRED_N} desired non (ré)appliqués ce cycle)"
fi

removed=0
if [ "$APPLIED_N" -gt 0 ]; then
  for cidr in "${!APPLIED_ID[@]}"; do
    # -v (test set-u-safe même sur DESIRED_ID assoc VIDE : cas revert-all) : appliqué mais plus désiré -> révoque
    if [ ! -v "DESIRED_ID[$cidr]" ]; then
      exempt_remove "$cidr"
      removed=$((removed + 1))
    fi
  done
fi

# ---- persiste le ledger f2b (ownership) — AVANT $APPLIED, borne du self-heal --
f2b_save_ledger

# ---- persiste l'état = DESIRED (borne dure du revert au prochain démarrage) --
STATE_TMP="$(mktemp)"
if [ "$DESIRED_N" -gt 0 ]; then
  for cidr in "${!DESIRED_ID[@]}"; do
    printf '%s\t%s\t%s\n' "$cidr" "${DESIRED_ID[$cidr]}" "${DESIRED_END[$cidr]}"
  done
fi > "$STATE_TMP"
chmod 0640 "$STATE_TMP" 2>/dev/null || true
mv -f "$STATE_TMP" "$APPLIED"

# =============================================================================
# 6) HEARTBEAT dead-man + résumé journald (jamais de token dans les logs)
# =============================================================================
# Le battement est une SOURCE du cycle suivant : son écriture ne doit pas interrompre celui-ci, et
# son échec ne doit pas passer inaperçu — au cycle suivant, il sera lu comme NON LU, donc armé.
if ! printf '%s' "$NOW" > "$HEARTBEAT" 2>/dev/null; then
  log "WARN: battement non persisté ($HEARTBEAT) — le cycle suivant traitera le recul d'horloge comme INDÉCIDABLE (fail-closed)"
fi
NFT_ON=0; nft_avail && NFT_ON=1
log "cycle mode=$MODE http=$http desired=$DESIRED_N applied_prev=$APPLIED_N ensured=$ensured removed=$removed refused=$refused nft_fail=$nft_fail skew=$SKEW_SUSPECT fails=$(cat "$FAILF" 2>/dev/null || echo 0) levers=cs:$CSCLI_OK,f2b:$F2B_OK,nft:$NFT_ON"

# ---- heartbeat visible au central (best-effort, calque origin-drop.sh) ------
if [ -d "$SPOOL" ]; then
  host="$(cat /proc/sys/kernel/hostname 2>/dev/null || echo "$HOSTN")"
  ev="{\"ts\":$NOW,\"source\":\"engagement-adapter\",\"category\":\"health\",\"severity\":0,\"message\":\"engagement-adapter sante: mode=$MODE desired=$DESIRED_N ensured=$ensured removed=$removed refused=$refused nft_fail=$nft_fail http=$http\",\"fields\":{\"mode\":\"$MODE\",\"desired\":$DESIRED_N,\"ensured\":$ensured,\"removed\":$removed,\"refused\":$refused,\"nft_fail\":$nft_fail,\"skew\":$SKEW_SUSPECT,\"http\":\"$http\",\"failcount\":$(cat "$FAILF" 2>/dev/null || echo 0)}}"
  st="$(mktemp "$SPOOL/.eadapt.XXXXXX" 2>/dev/null || true)"
  if [ -n "$st" ]; then
    printf '{"ts":%s,"host":"%s","kind":"events","events":[%s]}\n' "$NOW" "$host" "$ev" > "$st"
    chmod 0640 "$st" 2>/dev/null || true
    mv -f "$st" "$SPOOL/engagement-adapter-$NOW.json" 2>/dev/null || rm -f "$st"
  fi
fi

exit 0
