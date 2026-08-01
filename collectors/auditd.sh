#!/bin/sh
# Capteur Plume (PLUGIN) : ingere le LOG auditd -> events source=auditd.
# Dependance MINIMALE : lit uniquement le fichier que auditd ecrit deja. Skip si auditd absent.
# CAPTURE LARGE par defaut (execve + auth + comptes + TAMPER) : on n'ecarte RIEN au collecteur. auid
# (acteur) en CHAMP pour filtrer/agreger (auid!=4294967295 = sessions utilisateur).
# Option : PLUME_AUDIT_REAL_USER_ONLY=1 -> ne garder que les EXECVE d'un vrai utilisateur (auid defini).
#   (n'affecte QUE l'execve ; les events TAMPER sont TOUJOURS shippes, meme systeme.)
# BRANCHE TAMPER. Les regles de WATCH fichiers que vous posez (ex. dir=/etc perm=wa key=plume_etc, un
# repertoire de credentials key=plume_creds, un repertoire de donnees key=plume_data ; et
# shadow_changes/sudoers/plume_persist/boot_integrity si presentes) emettent des events type=PATH et des
# syscalls non-execve, qu'un simple parseur execve IGNORERAIT.
# On les correle (SYSCALL.key <-> PATH.name via l'id audit) et on shippe {key, path, syscall, exe, auid}
# en severity elevee (modif shadow/ld.so.preload = sev4). Incremental via offset d'octets (gere la rotation).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
LOG="${PLUME_AUDIT_LOG:-/var/log/audit/audit.log}"
OFF="$STATE_DIR/auditd.offset"
[ -r "$LOG" ] || plume_unavailable auditd missing-source "$LOG absent ou illisible (auditd non installe, non demarre, ou droits insuffisants) : aucun execve/tamper ne peut etre collecte"

# --- COUVERTURE DES REGLES : le collecteur peut LIRE le journal et rester AVEUGLE ------------------
# DEUXIEME angle mort, MESURE le 2026-08-01 sur la meme VM Ubuntu 24.04 : auditd installe, journal
# parfaitement lisible, collecteur vert... et `category=exec` A ZERO, parce que la seule regle execve
# du gabarit visait `arch=b32` sur un hote amd64. `plume_unavailable` ne peut pas l'attraper : le
# capteur n'est PAS incapable, il collecte tres bien un journal qui ne contient simplement aucun
# execve. L'incapacite s'est deplacee d'un cran, vers la POLITIQUE D'AUDIT DU NOYAU.
# Mais le collecteur PEUT le savoir : `auditctl -l` dit exactement quelles regles tournent. Ne pas le
# demander releverait du meme defaut que celui qu'on corrige — connaitre son angle mort et se taire.
# On le RAPPORTE donc en `category=config` (auto-report du collecteur, docs/CIM.md §2b), a cote des
# filtres deja publies. Requetable : `search source=auditd exec_rule_b64=0`.
# Emis ICI, AVANT tout arret anticipe : sur un hote sans aucune regle il n'y a rien a parser, donc le
# rapport de config plus bas n'est jamais atteint — c'est precisement le cas ou il faut parler.
# Dedup a bucket HORAIRE (meme raison que plume_report_availability : re-affirmer sans inonder).
_ar=""
command -v auditctl >/dev/null 2>&1 && _ar=$(auditctl -l 2>/dev/null || true)
_ar_n=$(printf '%s\n' "$_ar" | grep -c '^-' 2>/dev/null || true); _ar_n=${_ar_n:-0}
_ar_b64=0; _ar_b32=0
case "$_ar" in *"arch=b64 -S execve"*|*"arch=b64"*"execve"*) _ar_b64=1 ;; esac
case "$_ar" in *"arch=b32 -S execve"*|*"arch=b32"*"execve"*) _ar_b32=1 ;; esac
_arc_fields=$(printf '{"type":"collector-rule-coverage","collector":"auditd","audit_rules_loaded":%s,"exec_rule_b64":%s,"exec_rule_b32":%s,"note":"exec_rule_b64=0 sur un hote amd64 => category=exec restera VIDE quoi que fasse le collecteur : la politique d audit du noyau ne journalise aucun execve 64 bits. Correctif : sudo bash /usr/local/lib/plume/plume-audit-rules-load.sh (gabarit systemd/plume-audit.rules)."}' \
  "$_ar_n" "$_ar_b64" "$_ar_b32")
_arc_dd="auditrules-$(printf '%s' "$_arc_fields" | cksum | cut -d' ' -f1)-$((ts / 3600))"
spool_write "config-auditrules-$ts.json" "$(emit_event "$(printf '{"ts":%s,"source":"auditd","category":"config","severity":%s,"message":"couverture des regles auditd : %s regle(s) chargee(s), execve b64=%s b32=%s","dedup":"%s","fields":%s}' \
  "$ts" "$([ "$_ar_b64" = 1 ] && echo 0 || echo 2)" "$_ar_n" "$_ar_b64" "$_ar_b32" "$_arc_dd" "$_arc_fields")")" 2>/dev/null || true

size=$(wc -c < "$LOG" 2>/dev/null || echo 0)
prev=$(cat "$OFF" 2>/dev/null || echo 0)
case "$prev" in *[!0-9]*) prev=0 ;; esac
[ "$prev" -gt "$size" ] && prev=0
if [ "$prev" -ge "$size" ]; then printf '%s' "$size" > "$OFF"; plume_exit_nodata; fi

new=$(mktemp)
tail -c +"$((prev + 1))" "$LOG" 2>/dev/null > "$new" || true
printf '%s' "$size" > "$OFF"

# clés de WATCH tamper (file-integrity) que l'on shippe en plus des execve/auth/comptes.
TAMPER_KEYS="${PLUME_AUDIT_TAMPER_KEYS:-plume_etc|plume_creds|plume_data|shadow_changes|sudoers|plume_sensitive|plume_persist|boot_integrity}"

# ================================================================================================
# EXEC-DROP — filtre RÉVERSIBLE ALLOWLIST-TO-DROP du bruit exec coreutils.
# ------------------------------------------------------------------------------------------------
# POURQUOI : sur un hôte qui compile ou qui fait tourner beaucoup de scripts, `category=exec` domine
# largement le volume ingéré, et l'essentiel de ce flux est une poignée de coreutils / d'internes systemd
# martelés en boucle (grep/sed/date/cut/cat/env…) sans AUCUN consommateur de détection. Ce filtre les
# coupe CÔTÉ COLLECTEUR (l'ingest Plume seulement, PAS le /var/log/audit/audit.log de l'hôte : la
# forensique `ausearch` reste COMPLÈTE) pour tenir un budget de stockage contraint. Mesurez la part réelle
# sur VOTRE parc (`search source=auditd category=exec | stats count by exe`) avant d'activer.
#
# DÉFAUT = OFF (env vide) => comportement BYTE-IDENTIQUE (aucun event droppé). Poser
# PLUME_AUDITD_EXEC_DROP=1 active le filtre ; l'unset le désactive (100% réversible, zéro perte hôte).
#
# INVARIANT ANTI-ANGLE-MORT : ALLOWLIST-TO-DROP (défaut = KEEP). On DROP un execve UNIQUEMENT si TOUT
# est vrai : success=yes ET auid∈{0,1000} ET key=exec_tracking ET exe sous un préfixe STANDARD
# (/usr/bin|/usr/sbin|/usr/lib|/usr/libexec|/bin|/sbin|/lib) ET basename(exe) ∈ LISTE EFFECTIVE ci-dessous.
# Un exe JAMAIS-VU / hors-liste est TOUJOURS shippé => une dérive de liste ne peut JAMAIS aveugler en
# silence (le pire cas = "on ship un peu trop", jamais "on a raté une attaque").
#
# DEUX PALIERS — le paramètre par défaut ne doit JAMAIS aveugler
# la télémétrie de découverte / chasse-aux-secrets même avec l'interrupteur principal ON :
#   * PALIER 1 (DÉFAUT quand PLUME_AUDITD_EXEC_DROP=1) = bruit build/système NON-ÉQUIVOQUE uniquement.
#   * PALIER 2 (RECON-adjacent, gated derrière une 2e env PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON, défaut
#     vide=OFF) = primitives de DÉCOUVERTE / chasse-aux-secrets : grep find ls cat stat id
#     x86_64-linux-gnu-strings sed tee. Pour auid∈{0,1000} (foothold user/root compromis), ces exe portent
#     T1083 (File/Dir Discovery), T1057 (Process Discovery), T1552.001 (Creds-in-Files). Elles ne sont
#     ÉLIGIBLES au drop QUE si PLUME_AUDITD_EXEC_DROP **ET** PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON sont
#     posées. Par DÉFAUT elles SHIPPENT TOUJOURS (KEEP), interrupteur principal ON compris.
#   * `sed` (lit/transforme des fichiers = recon léger) et `tee` (écrit = persistence-adjacent) sont
#     délibérément en PALIER 2 (gated), pas en PALIER 1 — on penche vers le KEEP.
#   * `who` (System Owner/User Discovery) n'est dans AUCUN palier => shippe désormais TOUJOURS.
#
# NE JAMAIS FILTRER (garanti par le prédicat ci-dessus + garde KEEP explicite en défense-en-profondeur) :
#   - exec ÉCHOUÉ (success!=yes) — un échec est intéressant quel que soit le binaire.
#   - compte de SERVICE (auid=-1/unset) et tout key=svc_exec — signal anti-angle-mort, jamais réductible.
#   - exec depuis un répertoire INSCRIPTIBLE/non-standard (/tmp,/dev/shm,/var/tmp,/run,/home,./ …) —
#     exclu par l'exigence de préfixe standard (un /tmp/grep n'est PAS sous /usr/bin -> KEEP).
#   - tout INTERPRÉTEUR/shell, outil de PRIVILÈGE/PERSISTANCE/RÉSEAU/AUDIT/PERMISSION (garde KEEP).
#   - setuid/setgid : NON dérivable du record auditd -> honoré par l'allowlist-only (un binaire setuid
#     ou inconnu n'est jamais droppé par omission ; ne PAS inverser en block-list).
#
# AMPLEUR DU CUT — dépend ENTIÈREMENT de votre parc ; mesurez-la, ne la supposez pas :
#   `search source=auditd category=exec | stats count by exe | sort -count` puis comparez les basenames
#   au PALIER 1 et au PALIER 2 ci-dessous. Attendez-vous à ce que le PALIER 1 seul coupe SENSIBLEMENT
#   MOINS que PALIER 1+2 : les coreutils les plus fréquents sur un hôte de build (grep, sed, cat) sont
#   TOUS en PALIER 2, donc gardés par défaut. La sécurité prime ; le cut complet reste disponible via
#   le 2e opt-in explicite.
# LISTE DE DROP — PALIER 1 (basenames build/système NON-ÉQUIVOQUES, non-interpréteur/priv/persist/réseau/recon) :
AUDIT_EXEC_DROP_LIST_TIER1="date cut env uname expr tr gawk head sort wc basename dirname readlink cksum sha256sum sha1sum sha512sum md5sum seq iconv mkdir sleep dumpe2fs run-parts gettext bc pam-tmpdir-helper systemd systemd-executor systemd-tmpfiles systemd-sysctl systemd-sysusers systemd-cgroups-agent systemd-user-runtime-dir tail"
# LISTE DE DROP — PALIER 2 (RECON/chasse-secrets, gated ; T1083/T1057/T1552.001) — KEEP par défaut :
AUDIT_EXEC_DROP_LIST_TIER2="grep find ls cat stat id x86_64-linux-gnu-strings sed tee"
AUDIT_EXEC_DROP="${PLUME_AUDITD_EXEC_DROP:-}"                       # vide=OFF (byte-identique) ; non-vide=filtre actif
AUDIT_EXEC_DROP_RECON="${PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON:-}"   # vide=OFF (recon KEEP) ; non-vide=ajoute PALIER 2
# LISTE EFFECTIVE : PALIER 1 toujours ; + PALIER 2 UNIQUEMENT si le 2e gate recon est aussi posé.
AUDIT_EXEC_DROP_LIST="$AUDIT_EXEC_DROP_LIST_TIER1"
[ -n "$AUDIT_EXEC_DROP_RECON" ] && AUDIT_EXEC_DROP_LIST="$AUDIT_EXEC_DROP_LIST_TIER1 $AUDIT_EXEC_DROP_LIST_TIER2"
# ================================================================================================

# TSV : <sev> <cat> <fields> <message>  (auid sorti en champ -> filtre/agrege dans l'UI)
parsed=$(awk -v realonly="${PLUME_AUDIT_REAL_USER_ONLY:-0}" -v tk="$TAMPER_KEYS" \
             -v exdrop="$AUDIT_EXEC_DROP" -v dropexe="$AUDIT_EXEC_DROP_LIST" '
  function val(key){
    if (match($0, key "=\"[^\"]*\"")) { return substr($0, RSTART+length(key)+2, RLENGTH-length(key)-3) }
    if (match($0, key "=[^ ]+"))      { return substr($0, RSTART+length(key)+1, RLENGTH-length(key)-1) }
    return ""
  }
  function af(k,v){ if(v!=""&&v!="(null)"){ gsub(/[\\"\t]/,"",v); F=F (F==""?"":",") "\"" k "\":\"" v "\"" } }
  function mapsys(n){
    if(n=="2")return "open"; if(n=="257")return "openat"; if(n=="437")return "openat2";
    if(n=="87")return "unlink"; if(n=="263")return "unlinkat";
    if(n=="82")return "rename"; if(n=="264")return "renameat"; if(n=="316")return "renameat2";
    if(n=="90")return "chmod"; if(n=="268")return "fchmodat"; if(n=="92")return "chown"; if(n=="260")return "fchownat";
    if(n=="1")return "write"; if(n=="86")return "link"; if(n=="265")return "linkat"; if(n=="88")return "symlink"; if(n=="266")return "symlinkat";
    if(n=="188")return "setxattr"; if(n=="76")return "truncate"; if(n=="77")return "ftruncate"; if(n=="133")return "mknod"; if(n=="259")return "mknodat";
    return n;
  }
  # id audit (correle SYSCALL.key <-> PATH.name d un MEME event)
  { id=""; if (match($0,/audit\([0-9]+\.[0-9]+:[0-9]+\)/)) id=substr($0,RSTART,RLENGTH) }
  # --- TAMPER : enregistrement stateful (emis en END) ; NE consomme PAS la ligne (pas de next) ---
  /type=SYSCALL/ {
    tkk=val("key");
    if (tkk ~ tk) {
      TID[id]=1; TKEY[id]=tkk; TEXE[id]=val("exe"); TAUID[id]=val("auid"); TUID[id]=val("uid");
      TSY[id]=val("syscall"); TSUCC[id]=val("success"); TCOMM[id]=val("comm");
    }
  }
  /type=PATH/ {
    nm=val("name"); nt=val("nametype");
    if (nm!="" && id!="") {
      if (!(id in TPATH)) TPATH[id]=nm;                          # fallback (souvent le PARENT dir)
      if (nt!="PARENT" && nm !~ /\/$/) TPATH[id]=nm;             # la CIBLE reelle (create/normal/delete)
      if (nm ~ /shadow|sudoers|ld\.so\.preload|passwd|gshadow|authorized_keys|\.service|\.timer|pam\.d|rc\.local|rancher/) TPATH[id]=nm;  # priorite chemins sensibles
    }
  }
  # --- EXECVE (inchange : filtrage real-user-only conserve) ---
  /type=SYSCALL/ && (/ syscall=59 / || / syscall=322 /) {
    exe=val("exe"); if (exe=="") next;
    comm=val("comm"); auid=val("auid"); uid=val("uid"); succ=val("success"); k=val("key");
    # svc_exec = exec par un compte SERVICE/DAEMON (auid non defini) d un shell/interpreteur/outil reseau
    # (limite connue : une regle exec_tracking filtree sur auid ne couvre pas les comptes de service). On NE le DROP JAMAIS,
    # meme en real-user-only : c est precisement le signal auid=unset que l on veut (regles -k svc_exec).
    if (realonly=="1" && (auid=="4294967295" || auid=="-1" || auid=="") && k !~ /svc_exec/) next;
    # EXEC-DROP : allowlist-to-drop du bruit coreutils. Défaut OFF (exdrop vide). Voir le bloc
    # de doc + AUDIT_EXEC_DROP_LIST dans le shell. Garde KEEP = défense-en-profondeur : même si un nom
    # se glissait dans la liste de drop, ces familles (interpréteurs/priv/persist/réseau/audit/permission)
    # ne sont JAMAIS droppées. Le reste des carve-outs (échec/svc/inscriptible) est porté par le prédicat.
    if (exdrop != "") {
      bn=exe; sub(/.*\//,"",bn);
      keepx = (bn ~ /^(python[0-9.]*|perl|ruby[0-9.]*|php[0-9]*|lua[0-9.]*|tclsh[0-9.]*|node|Rscript|dash|bash|sh|zsh|ksh|env-shell|sudo|su|pkexec|doas|passwd|chpasswd|useradd|usermod|groupadd|visudo|newgrp|crontab|at|systemctl|systemd-run|update-rc\.d|auditctl|ausearch|auditd|augenrules|setenforce|chmod|chown|chattr|setfacl|setcap|nc|ncat|netcat|socat|curl|wget|ssh|scp|sftp|telnet|ftp|base64|xxd|openssl)$/);
      if (!keepx && succ=="yes" && (auid=="0" || auid=="1000") && k=="exec_tracking" \
          && exe ~ /^\/(usr\/(bin|sbin|lib|libexec)|bin|sbin|lib)\// \
          && index(" " dropexe " ", " " bn " ") > 0) {
        DROPPED++; next;
      }
    }
    sev=1; if (k ~ /priv|escal|susp/) sev=2; if (succ=="no") sev=2; if (k ~ /svc_exec/) sev=3;
    msg="exec: " exe " (" comm ") auid=" auid; if (succ=="no") msg=msg " ECHEC";
    if (k!="" && k!="(null)") msg=msg " key=" k;
    gsub(/[\\"]/,"",msg);
    F=""; af("auid",auid); af("uid",uid); af("exe",exe); af("comm",comm); af("key",k); af("success",succ); af("syscall","execve"); af("action",(succ=="no")?"failure":"success");
    print sev "\texec\t" F "\t" msg; next
  }
  /type=ADD_USER/ || /type=DEL_USER/ || /type=USER_CHAUTHTOK/ || /type=USER_MGMT/ || /type=ROLE_ASSIGN/ || /type=ADD_GROUP/ {
    t=$1; sub(/type=/,"",t); acct=val("acct"); auid=val("auid"); uid=val("uid");
    msg="compte: " t " acct=" acct " auid=" auid; gsub(/[\\"]/,"",msg);
    F=""; af("auid",auid); af("uid",uid); af("acct",acct); af("atype",t); af("action","success");
    print 2 "\taccount\t" F "\t" msg; next
  }
  /type=USER_AUTH/ && /res=failed/ {
    acct=val("acct"); exe=val("exe"); auid=val("auid"); addr=val("addr");
    msg="auth echouee: acct=" acct " via " exe; gsub(/[\\"]/,"",msg);
    F=""; af("auid",auid); af("acct",acct); af("exe",exe); af("addr",addr); af("res","failed"); af("action","failure");
    print 2 "\tauth\t" F "\t" msg; next
  }
  END {
    # EXEC-DROP self-report : sentinelle best-effort (interceptée par le shell, jamais émise
    # comme event) portant le nb d execve droppes ce run -> expose dans l event config collection-reducing.
    if (DROPPED>0) print "0\t__auditd_dropcount__\t" DROPPED "\tdrop";
    for (id in TID) {
      key=TKEY[id]; path=(id in TPATH)?TPATH[id]:""; sy=mapsys(TSY[id]);
      exe=TEXE[id]; auid=TAUID[id]; uid=TUID[id]; succ=TSUCC[id];
      sev=3;
      if (path ~ /shadow|ld\.so\.preload|gshadow/) sev=4;
      else if (key ~ /plume_creds|sudoers|plume_persist|plume_sensitive|boot_integrity/) sev=4;
      else if (path ~ /sudoers|authorized_keys|pam\.d|rc\.local/) sev=4;
      msg="tamper[" key "]: " (path!=""?path:"?") " syscall=" sy " exe=" exe " auid=" auid; if (succ=="no") msg=msg " ECHEC";
      gsub(/[\\"]/,"",msg);
      F=""; af("key",key); af("path",path); af("syscall",sy); af("exe",exe); af("comm",TCOMM[id]); af("auid",auid); af("uid",uid); af("success",succ); af("action",(succ=="no")?"failure":"success");
      print sev "\ttamper\t" F "\t" msg;
    }
  }
' "$new" | head -"${PLUME_AUDIT_MAX:-4000}")
rm -f "$new"
[ -z "$parsed" ] && plume_exit_nodata

events=""; EXEC_DROPPED=0; TAB=$(printf '\t')
while IFS="$TAB" read -r sev cat fields msg; do
  # EXEC-DROP self-report : capte la sentinelle du nb droppé -> event config, PAS un event.
  if [ "${cat:-}" = "__auditd_dropcount__" ]; then EXEC_DROPPED="${fields:-0}"; continue; fi
  [ -z "${msg:-}" ] && continue
  mj=$(json_escape "$msg")
  fj=""; [ -n "${fields:-}" ] && fj=",\"fields\":{$fields}"
  sip=""; case "${fields:-}" in *'"addr":"'*) ip=$(printf '%s' "$fields" | sed -n 's/.*"addr":"\([0-9.]*\)".*/\1/p'); [ -n "$ip" ] && sip=",\"src_ip\":\"$ip\"" ;; esac
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"auditd\",\"category\":\"$cat\",\"severity\":$sev,\"message\":\"$mj\"$sip$fj}"
done <<EOF
$parsed
EOF

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=auditd category=config) ------------
# AVANT l'early-exit. Surface PLUME_AUDIT_REAL_USER_ONLY dans le panneau read-only. VISIBILITE cote
# daemon, CONTROLE ici. Dedup par empreinte. collection-reducing quand =1 (drop execve service-acct,
# SAUF svc_exec + TOUT TAMPER : carve-out anti-angle-mort integre, surface aussi).
cfg_ruo="${PLUME_AUDIT_REAL_USER_ONLY:-0}"
# EXEC-DROP : surface la config du filtre allowlist-to-drop (transparence anti-angle-mort) —
# les DEUX paliers sont EXPLICITES et TOUJOURS présents (jamais tronqués) : exec_drop (on/off),
# exec_drop_include_recon (on/off), la liste STATIQUE palier 1, la liste STATIQUE palier 2 (recon/gated),
# et la liste EFFECTIVE (palier 1, ou palier 1+2 si recon ON) => un défenseur voit la surface d'angle
# mort EXACTE quelle que soit la position des interrupteurs. Visible en console, jamais un angle mort silencieux.
cfg_exdrop="${PLUME_AUDITD_EXEC_DROP:-}"; [ -n "$cfg_exdrop" ] && cfg_exdrop_on="1" || cfg_exdrop_on="0"
cfg_recon="${PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON:-}"; [ -n "$cfg_recon" ] && cfg_recon_on="1" || cfg_recon_on="0"
cfg_fields=$(printf '{"type":"collection-reducing","collector":"auditd","filters":{"real_user_only":"%s","exec_drop":"%s","exec_drop_include_recon":"%s"},"exec_drop_dropped_this_run":%s,"exec_drop_list_tier1":"%s","exec_drop_list_tier2_recon":"%s","exec_drop_list_effective":"%s","carve_out":"svc_exec + auid=-1 + exec echoue + exec depuis dir inscriptible + interpreteurs/priv/reseau/audit/permission + RECON/chasse-secrets (grep/find/ls/cat/stat/id/strings/sed/tee : palier 2, KEEP tant que exec_drop_include_recon non pose) + TOUS les events TAMPER : TOUJOURS shippes (anti-angle-mort)","note":"exec_drop=1 -> DROP palier 1 (build/systeme non-equivoque) des coreutils benins (success=yes, auid in {0,1000}, exec_tracking, prefixe standard, basename in tier1). exec_drop_include_recon=1 ajoute le palier 2 (recon : T1083/T1057/T1552.001) SEULEMENT si exec_drop aussi pose. defaut vide=OFF byte-identique ; recon defaut KEEP meme interrupteur principal ON. real_user_only=1 -> drop execve comptes de service (hors svc_exec/TAMPER)."}' \
  "$(json_escape "$cfg_ruo")" "$cfg_exdrop_on" "$cfg_recon_on" "${EXEC_DROPPED:-0}" "$(json_escape "$AUDIT_EXEC_DROP_LIST_TIER1")" "$(json_escape "$AUDIT_EXEC_DROP_LIST_TIER2")" "$(json_escape "$AUDIT_EXEC_DROP_LIST")")
cfg_dd="cfg-auditd-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"auditd","category":"config","severity":0,"message":"config collecteur auditd (filtres de collecte)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-auditd-$ts.json" "$(emit_event "$cfg_event")"

[ -z "$events" ] && plume_exit_nodata

spool_write "auditd-$ts.json" "$(emit_event "$events")"
