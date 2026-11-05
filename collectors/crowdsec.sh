#!/bin/sh
# plume-source: crowdsec
# plume-emits: fields=acq_counters_reset,acq_frozen_sources,acq_parsed,acq_parsed_delta,acq_pour,acq_pour_delta,acq_reads,acq_reads_delta,acq_sources,acq_unparsed,acq_unparsed_delta,acq_verdict,acq_whitelisted,acq_whitelisted_delta,acquisition,action,agent_ready,lapi_ok,last_alert_age_s,scenarios_broken,scenarios_loaded
# Capteur Plume : INGÈRE les alertes CrowdSec (cscli) -> events source=crowdsec.
# On NE refait PAS la détection/le ban : CrowdSec reste l'IPS, le SOC corrèle/notifie/investigue.
# Requiert cscli + jq. ROOT. Optionnel (skip si absents). Dédup par id d'alerte (idempotent).
#
# DEAD-MAN'S-SWITCH : à CHAQUE run (timer 5 min) on ship AUSSI un battement de SANTÉ
# (source=crowdsec category=health) MÊME quand 0 alerte -> Plume distingue « 0 attaque (normal) » de
# « moteur CrowdSec mort/cassé ». Le SILENCE de ce battement (>~25 min) lève une alerte MUET (collecteur
# CONTINU crowdsec-health, cf. main.rs) ; scenarios_broken>0 lève une alerte de détection (T1562.001).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
NS="${PLUME_CROWDSEC_NS:-crowdsec}"; LAPI="${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
AGENT="${PLUME_CROWDSEC_AGENT:-crowdsec-agent}"   # le HUB (scénarios) vit sur l'AGENT, pas la LAPI
# Commande cscli selon le MODE de déploiement : PLUME_CSCLI explicite > cscli sur l'hôte > k3s (exec dans
# le pod LAPI : en k3s CrowdSec tourne en pod, pas de cscli sur l'hôte) > skip. # shellcheck disable=SC2086
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_cmd() { $PLUME_CSCLI "$@"; }
elif command -v cscli >/dev/null 2>&1; then cscli_cmd() { cscli "$@"; }
elif command -v k3s >/dev/null 2>&1 && k3s kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { k3s kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
elif command -v kubectl >/dev/null 2>&1 && kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
else plume_unavailable crowdsec missing-dependency "aucun acces a cscli (ni binaire local, ni deploiement LAPI joignable)"; fi
# Résolution de l'AGENT (hub/scénarios + LOG) pour le battement de SANTÉ. L'agent CrowdSec est un DaemonSet
# (ds/) — PAS un Deployment — donc on sonde ds/ puis deploy/ (jamais un nom de pod figé). host/explicite
# (cscli local) voient le hub local ; sinon on exec/log dans la ressource agent kube. # shellcheck disable=SC2086
KUBE=""
if command -v k3s >/dev/null 2>&1; then KUBE="k3s kubectl"
elif command -v kubectl >/dev/null 2>&1; then KUBE="kubectl"; fi
AGENT_REF=""
_cs_ko=""    # lectures PRESENTES mais en echec ce passage, avouees en une fois a la fin
# S36 — « JE N'AI PAS TROUVE L'AGENT » ET « JE N'AI PAS PU LE CHERCHER » RENDAIENT LE MEME MOT.
# Quand aucun outil kube n'est la, `KUBE` est vide et il n'y a rien a chercher : c'est le mode hote,
# nominal, et on se tait. Mais quand un outil kube EST la et que ni le DaemonSet ni le Deployment ne
# repondent, le chemin du LOG de l'agent est perdu — or ce log est le SEUL signal fiable d'un
# scenario qui echoue a charger (l'en-tete de ce fichier le dit et le mesure). Le capteur publiait
# alors `scenarios_broken: -1` a la severite 0 : un inconnu presente comme du calme. L'inconnu reste
# publie tel quel — une regle livree en depend — mais il est desormais ACCOMPAGNE d'un aveu.
# LE COUT EST NOMME : un hote portant `kubectl` ET un CrowdSec natif avouera ce trou a chaque
# passage. Ce n'est pas une fausse alerte — sur cet hote, les erreurs de chargement de scenarios ne
# sont effectivement PAS mesurees — et la dedup horaire du canal en borne le volume.
if [ -n "$KUBE" ]; then
  if $KUBE -n "$NS" get ds "$AGENT" >/dev/null 2>&1; then AGENT_REF="ds/$AGENT"
  elif $KUBE -n "$NS" get deploy "$AGENT" >/dev/null 2>&1; then AGENT_REF="deploy/$AGENT"
  else _cs_ko="$_cs_ko journal/agent"; fi
fi
ALOG_C="${PLUME_CROWDSEC_AGENT_CONTAINER:-crowdsec-agent}"   # conteneur agent (exec/logs ciblés)
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_agent() { $PLUME_CSCLI "$@"; }
elif command -v cscli >/dev/null 2>&1; then cscli_agent() { cscli "$@"; }
elif [ -n "$AGENT_REF" ]; then cscli_agent() { $KUBE -n "$NS" exec "$AGENT_REF" -c "$ALOG_C" -- cscli "$@"; }
else cscli_agent() { cscli_cmd "$@"; }   # repli : pas d'agent kube distinct -> la LAPI porte le hub
fi
# Logs de l'AGENT pour DÉTECTER le deadlock moteur. DÉCISIF (validé crowdsec v1.7.8) : un scénario qui ÉCHOUE
# à charger ses data-files reste status:"enabled" / tainted:null dans `hub list` -> le hub NE voit PAS la
# panne. Seul signal fiable = le LOG agent ('not found in expr library' / 'unable to init data for file').
# Lisible seulement en k3s/kubectl (ds|deploy/$AGENT) ; sinon false -> scenarios_broken=-1 (inconnu, la règle
# la regle de sante ne fire pas sur transitoire). NB FENÊTRE --since=15m : capte les erreurs de (re)chargement récentes
# (startup/SIGHUP/évaluation) ; backstop pour une cécité durable = l'alerte MUET du capteur CONTINU
# crowdsec-health (silence du battement) si l'agent meurt vraiment.
if [ -n "$AGENT_REF" ]; then agent_logs() { $KUBE -n "$NS" logs "$AGENT_REF" -c "$ALOG_C" --since=15m; }
else agent_logs() { false; }   # host/explicite : pas de chemin log pod -> scenarios_broken=-1 (inconnu)
fi
command -v jq >/dev/null 2>&1 || plume_unavailable crowdsec missing-dependency "jq absent"
plume_init
# P10.32-k — SEUIL DE « LIT, MAIS SURTOUT EN LISTE BLANCHE », en pour cent des lignes analysées. Au-delà de
# neuf lignes sur dix écartées, la détection ne porte plus que sur un résidu : c'est un ordre de grandeur de
# conception, pas une valeur relevée sur une installation. Une installation dont le trafic légitime vient
# massivement d'adresses privées (réseau interne servi sans mandataire) le relève ; à 100, il ne part plus que
# lorsque toutes les lignes analysées sont en liste blanche et qu'une au moins a pourtant été versée.
CS_WL_SEUIL="${PLUME_CROWDSEC_WHITELIST_SHARE_MAX:-90}"
case "$CS_WL_SEUIL" in
  [1-9]|[1-9][0-9]|100) ;;
  *) plume_reglage_illisible crowdsec PLUME_CROWDSEC_WHITELIST_SHARE_MAX "$CS_WL_SEUIL" 90 "l'environnement du capteur"; CS_WL_SEUIL=90 ;;
esac
# P10.32-k (prolongation, mesuré en production le 2026-11-04) — DURÉE SANS AUCUNE LIGNE AUX SCÉNARIOS, en
# heures, avant que `tout_en_liste_blanche` refuse de conclure. Un site dont un CDN arrête les robots en amont
# ne voit, la plupart des heures, aucune ligne à adresse publique : refuser à chaque passage (sévérité 3, aveu
# horaire) criait un fait de quelques heures comme une panne. Sous ce seuil le verdict se nomme
# `en_liste_blanche_sous_le_seuil` (sévérité 1, durée et seuil dits, aucun aveu) ; au seuil, le refus d'avant.
# 0 = refus immédiat (le comportement d'avant). Défaut 24 : une journée entière sans une seule ligne aux
# scénarios n'est plus un creux de trafic, c'est un ordre de grandeur de conception, pas une valeur relevée.
CS_SANS_SCEN_H="${PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES:-24}"
case "$CS_SANS_SCEN_H" in
  0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]) ;;
  *) plume_reglage_illisible crowdsec PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES "$CS_SANS_SCEN_H" 24 "l'environnement du capteur"; CS_SANS_SCEN_H=24 ;;
esac

# ── 1) ALERTES (chemin existant) : ne SORT PLUS si vide -> le battement de santé ci-dessous part TOUJOURS.
# S36 — `|| echo ''` REMPLACAIT LE STATUT DE LA LECTURE PAR CELUI D'UN `echo`, c'est-a-dire par un
# succes. `lapi_ok` etait ensuite deduit du fait que la sortie soit NON VIDE : une LAPI joignable
# n'ayant aucune alerte rend `[]` — non vide — donc le drapeau restait juste par accident de format.
# Il est desormais tire du CODE DE RETOUR, qui est ce qu'on voulait dire, et l'echec est AVOUE :
# `agent_ready` seul decidait de la severite du battement, si bien qu'un agent interrogeable et une
# LAPI muette produisaient le message « CrowdSec santé », rassurant, sur une lecture qui avait rate.
if raw=$(cscli_cmd alerts list --limit 0 -o json 2>/dev/null); then
  lapi_ok=1
else
  lapi_ok=0; raw=''; _cs_ko="$_cs_ko alertes/LAPI"
fi
[ -z "$raw" ] && raw='[]'
events=""
n=0
tmpf=$(mktemp)
# S36 — L'ECHEC DU DECODAGE ETAIT LA MEME CHOSE QUE « AUCUNE ALERTE ». La branche `else` de ce test
# ne faisait RIEN : un `jq` absent, casse, ou une reponse LAPI dont la forme a change produisaient
# zero event, exactement comme une periode sans la moindre alerte. Le `else` DIT maintenant ce qu'il
# constate ; l'aveu part plus bas, avec les autres, en une fois.
if ! printf '%s' "$raw" | jq -r '.[] | [ (.id|tostring), (.source.value // "-"), (.scenario // "-") ] | @tsv' > "$tmpf" 2>/dev/null; then
  _cs_ko="$_cs_ko alertes/forme"
else
  TAB=$(printf '\t')
  while IFS="$TAB" read -r id ip scen; do
    [ -z "$id" ] && continue
    n=$((n + 1)); [ "$n" -gt 200 ] && break
    m=$(json_escape "$(printf 'CrowdSec: %s (src %s)' "$scen" "$ip")")
    # P10.32-i — `.source.value` et `.id` viennent de la LAPI, et le filtre `*.*|*:*` ne garde qu'un
    # point ou deux-points : il ne prouve l'absence ni de guillemet ni d'antislash. Une valeur
    # `x","severity":0,"category":"info","z":"` reecrivait severite et categorie (cle dupliquee, la
    # derniere gagne). Les deux sont donc echappees la ou elles entrent dans le JSON.
    ipf=""
    case "$ip" in *.*|*:*) ipf=",\"src_ip\":\"$(json_escape "$ip")\"" ;; esac
    idj=$(json_escape "$id")
    events="$events${events:+,}{\"ts\":$ts,\"source\":\"crowdsec\",\"category\":\"network\",\"severity\":3,\"message\":\"$m\",\"dedup\":\"crowdsec-$idj\"$ipf,\"fields\":{\"action\":\"blocked\"}}"
  done < "$tmpf"
fi
rm -f "$tmpf"

# ── 2) SANTÉ (dead-man's-switch) : interroge l'AGENT (hub + LOG) + la LAPI, ship UN battement à CHAQUE run
# (même 0 alerte). scenarios_loaded = `cscli hub list -o json | .scenarios | length` (INFORMATIF, ~59 sain ;
# PAS un signal de panne : le hub reste « enabled » même scénario cassé). scenarios_broken = ERREURS DE
# CHARGEMENT lues dans le LOG agent (seul signal fiable, cf. ci-dessus). agent_ready = hub interrogeable ;
# lapi_ok = `alerts list` a répondu ci-dessus ; last_alert_age_s informatif.
agent_ready=0; scen_loaded=-1; scen_broken=-1
# S36 — meme correction, meme raison : le statut du `hub list` etait remplace par celui d'un `echo`.
# Une sortie vide se lisait « agent non interrogeable », ce qui est le bon verdict, mais il n'etait
# accompagne d'AUCUN aveu : le battement disait « INJOIGNABLE » a la severite 3 et rien ne remontait
# par le canal de couverture, la ou une regle livree alerte deja.
if ! hub=$(cscli_agent hub list -o json 2>/dev/null); then
  hub=''; _cs_ko="$_cs_ko hub/agent"
fi
if [ -n "$hub" ]; then
  agent_ready=1
  scen_loaded=$(printf '%s' "$hub" | jq -r '(.scenarios // []) | length' 2>/dev/null || echo -1)
fi
# scenarios_broken = nb de lignes d'erreur de chargement dans le log agent (15 min). -1 si log inaccessible
# (modes host/explicite, RBAC, réseau) -> inconnu -> la règle de santé (CAST(-1)>0 faux) ne fire pas sur transitoire.
if logs=$(agent_logs 2>/dev/null); then
  scen_broken=$(printf '%s\n' "$logs" | grep -cE 'not found in expr library|unable to init data' || true)
  [ -z "$scen_broken" ] && scen_broken=0
fi
# ── 2 bis) CE QUE CROWDSEC LIT (P10.32-g). Le battement disait que le moteur TOURNE, jamais qu'il LIT.
# Une acquisition tombée à zéro ligne — fichier de journal renommé à la recréation d'un pod, chemin
# faux, montage perdu — laissait la source « fraîche » avec 0 alerte : indiscernable du calme.
# `cscli metrics show acquisition -o json` porte, par source d'acquisition, les compteurs `reads`,
# `parsed`, `unparsed`, `pour`, `whitelisted` (repli `cscli metrics -o json`, forme des versions qui
# n'ont pas `metrics show`).
#
# QUI LES PORTE, PAR MODE. Les métriques d'acquisition vivent dans le processus qui LIT les journaux :
# l'AGENT. En k3s c'est le DaemonSet agent, pas la LAPI — d'où `cscli_agent`, déjà résolu plus haut
# dans le même ordre (PLUME_CSCLI > cscli local > exec dans l'agent kube). En hôte natif (systemd) et
# en Docker, agent et LAPI sont le MÊME processus : `cscli` local, ou `PLUME_CSCLI` (par exemple
# `docker exec <conteneur> cscli` — le nom du conteneur est celui de l'installation, pas du dépôt).
# LIMITE DITE : `exec ds/<agent>` vise UN pod du DaemonSet ; sur un parc multi-nœuds, les autres agents
# ne sont pas lus par ce passage.
#
# LA DIFFÉRENCE SE CALCULE CONTRE L'ÉTAT LOCAL DU CAPTEUR (`$STATE/crowdsec-acquisition.json`), mis en
# attente et écrit APRÈS la publication, comme les filigranes des autres capteurs. Les compteurs
# repartent de zéro au redémarrage de l'agent : un compteur qui DIMINUE est un redémarrage, et la
# différence de cette source vaut alors sa valeur courante — jamais un négatif. Une source neuve part
# de zéro. Au premier passage (aucun état, ou état illisible), les différences valent -1 (inconnues).
#
# VERDICT `acq_verdict` : `lit` · `premier_passage` (aucun état, et au moins une ligne lue depuis le
# démarrage de l'agent) · `aucune_lecture` · `aucune_analyse` · `aucune_source` · `illisible`, et depuis
# `P10.32-k` `tout_en_liste_blanche` · `surtout_liste_blanche` · `en_liste_blanche_sous_le_seuil` (plus bas). Les
# quatre de la première ligne après `premier_passage`, et `tout_en_liste_blanche`, sont un REFUS DE CONCLURE :
# l'absence d'alerte ne prouve plus rien. Ils partent par le canal déjà livré
# (`plume_lecture_partielle`, donc `de-collector-unavailable`), relèvent la sévérité du battement à 3,
# et n'avancent PAS l'état. Une source isolée figée alors que d'autres lisent — typiquement le fichier
# d'un ancien pod, que l'agent garde jusqu'à son redémarrage — est NOMMÉE dans `acq_frozen_sources`,
# sans alerte : elle n'aveugle pas le moteur. AU PREMIER PASSAGE AUSSI : faute d'état, il n'y a pas de
# différence, mais une source qui n'a lu AUCUNE ligne depuis le démarrage de l'agent alors que d'autres lisent
# est la même acquisition à zéro ligne — elle était tue jusqu'au passage suivant (`P10.32-g`), elle est nommée.
# `aucune_analyse` : des lignes lues, mais AUCUNE analysée ni écartée par liste blanche sur l'intervalle
# (au premier passage : depuis le démarrage) — parseur cassé, format de journal changé. Rien n'atteint
# les scénarios : c'est le même aveuglement que l'absence de lecture. LIMITE DITE : le jugement porte
# sur les totaux ; UNE source dont le parseur est cassé parmi d'autres qui analysent reste visible dans
# son détail (`unparsed_delta` == `reads_delta`), sans refus.
# LE COÛT EST NOMMÉ : une installation réellement sans trafic pendant un intervalle entier refusera de
# conclure ; la dédup horaire du canal en borne le volume, et c'est exact — rien n'a été observé. Pour
# `tout_en_liste_blanche`, ce coût était payé à CHAQUE passage (mesuré le 2026-11-04 : sévérité 3, aveu horaire,
# sur un site dont un CDN arrête les robots) ; il ne l'est plus qu'au-delà du seuil de durée. LE PRIX DE CE
# SEUIL, DIT : pendant jusqu'à 24 h (par défaut), un moteur réellement aveuglé par un mandataire ne refuse pas —
# il le dit en sévérité 1, avec la répartition qui nomme la liste privée. Une mise à niveau ou un horodatage
# perdu repartent de zéro : la durée réelle peut être plus longue que celle dite.
# P10.32-k — LIRE N'EST PAS DÉTECTER QUAND LA LISTE BLANCHE ABSORBE TOUT. Derrière un mandataire ou un
# tunnel, l'adresse cliente que CrowdSec lit dans le journal est celle du RELAIS — une adresse privée — et
# la liste blanche des adresses privées écarte la ligne avant les scénarios. Le moteur lit, analyse, et ne
# peut rien détecter ; `lit` se lisait comme du calme. Deux verdicts de plus, sur la même base que les
# autres (l'intervalle, ou depuis le démarrage au premier passage) :
# DEUX FORMES DE COMPTAGE, DÉPARTAGÉES PAR `reads`. Selon la version, une ligne en liste blanche est comptée
# PARMI les analysées (`whitelisted` ⊆ `parsed`, et `reads` = `parsed` + `unparsed`) ou À CÔTÉ d'elles
# (`reads` = `parsed` + `unparsed` + `whitelisted`). Dès qu'il y a des lignes en liste blanche, `reads` les
# distingue : `reads` >= `parsed` + `unparsed` + `whitelisted` est la forme disjointe. On en tire les lignes
# analysées HORS liste blanche (`parsed`, ou `parsed` - `whitelisted`) et le total analysé (`parsed` +
# `whitelisted`, ou `parsed`) ; un échantillon incohérent (plus d'écartées que d'analysées dans la forme
# incluse) est borné par max(analysées, écartées), donc à 100 %.
#   `tout_en_liste_blanche` — des lignes en liste blanche, AUCUNE analysée hors liste blanche, et aucune
#     versée à un scénario (`pour` nul ; une ligne versée prouve que la détection reçoit quelque chose, même
#     quand les compteurs se décalent d'un relevé à l'autre), DEPUIS AU MOINS `PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES`
#     (défaut 24, 0 = dès le premier passage). REFUS DE CONCLURE, même canal, même sévérité que les quatre
#     autres ; cause fermée `forme_inconnue`, et la cause DITE suit la répartition par liste blanche (2 ter) :
#     mandataire seulement si tout part dans `crowdsecurity/whitelists`. La durée est dite.
#   `en_liste_blanche_sous_le_seuil` — le même constat depuis MOINS que ce seuil : sévérité 1, durée, seuil,
#     répartition et cause dans le message, AUCUN aveu, et l'état N'AVANCE PAS (la fenêtre continue de courir,
#     le refus part au seuil sans attendre d'autre signal).
#     SAUF horodatage absent ou illisible qui ne peut pas s'inscrire (état non inscriptible, 2 quater) : la
#     durée ne courrait jamais, le verdict reste `tout_en_liste_blanche` (refus, sévérité 3, aveu) AVANT le
#     seuil, et l'échec d'écriture est avoué (`etat/horodatage`).
#   `surtout_liste_blanche` — la part en liste blanche (écartées / total analysé) ATTEINT le seuil
#     `PLUME_CROWDSEC_WHITELIST_SHARE_MAX` : le moteur détecte encore sur le reste, ce n'est pas un refus ;
#     la sévérité du battement monte à 2 et le message nomme la cause probable. L'état avance.
# CE QUE CES VERDICTS NE VOIENT PAS : ils jugent les TOTAUX de toutes les sources. Une source entièrement en
# liste blanche au milieu d'autres qui détectent laisse le verdict à `lit` ; seul son détail (`acquisition`,
# `whitelisted` et `parsed` de la source) le montre.
# La part est dite dans le MESSAGE du battement, à chaque passage où elle se calcule : un champ neuf doit
# entrer dans l'inventaire de collecte du démon (`daemon/src/collected.rs`), que ce changement ne touche
# pas ; `acq_whitelisted(_delta)` et `acq_parsed(_delta)`, déjà émis, la portent en chiffres.
# Le détail par source (`acquisition`) et `acq_frozen_sources` sont bornés à 100 entrées chacun (le
# roulement des pods multiplie les fichiers de conteneur) ; `acq_sources` porte le compte réel et les
# totaux couvrent TOUTES les sources.
# CE QUE LA BORNE COÛTE EN STOCKAGE — CALCULÉ, pas relevé. Une entrée du détail pèse environ 200 octets
# plus le nom de sa source ; pour des noms de 100 à 160 caractères (fichiers de conteneur), le détail
# plein fait de 30 à 36 Ko et `acq_frozen_sources` pleine de 10 à 16 Ko, soit au pire de 40 à 52 Ko par
# battement. Au rythme du minuteur livré (`plume-crowdsec.timer`, toutes les 5 min, 288 passages par
# jour), c'est de 11 à 15 Mio par jour et par hôte avant compression, à multiplier par la rétention du
# central. Une installation à quelques sources reste de l'ordre de 0,4 Ko par source et par battement.
ACQ_STATE="$STATE/crowdsec-acquisition.json"
acq_verdict=illisible; acq_cause=source_illisible
acq_n=-1; acq_r=-1; acq_p=-1; acq_u=-1; acq_po=-1; acq_w=-1
acq_dr=-1; acq_dp=-1; acq_du=-1; acq_dpo=-1; acq_dw=-1
acq_reset=false; acq_frozen='[]'; acq_detail='[]'; acq_etat=''; acq_part=-1
if acq_raw=$(cscli_agent metrics show acquisition -o json 2>/dev/null) || acq_raw=$(cscli_agent metrics -o json 2>/dev/null); then
  acq_prev=null
  if [ -r "$ACQ_STATE" ]; then
    acq_prev=$(jq -c 'if type == "object" and all(.[]; type == "object" and all(.[]; type == "number")) then . else null end' "$ACQ_STATE" 2>/dev/null) || acq_prev=null
    [ -n "$acq_prev" ] || acq_prev=null
  fi
  # shellcheck disable=SC2016
  if acq_out=$(printf '%s' "$acq_raw" | jq -c --argjson prev "$acq_prev" --argjson seuil "$CS_WL_SEUIL" '
      def n: if . == null then 0 elif type == "number" then . else error("compteur non numerique") end;
      ["reads","parsed","unparsed","pour","whitelisted"] as $K
      | if type != "object" then error("forme") else . end
      | (.acquisition // {}) as $a
      | if ($a | type) != "object" then error("forme") else . end
      | ($prev | type == "object") as $has
      | [ $a | to_entries[]
          | if (.value | type) != "object" then error("forme") else . end
          | .key as $s | .value as $v
          | (reduce $K[] as $k ({}; .[$k] = ($v[$k] | n))) as $c
          | (if $has then ($prev[$s] // {}) else null end) as $p
          | ($p != null and any($K[]; $c[.] < ($p[.] // 0))) as $reset
          | {source: $s, c: $c, reset: $reset,
             d: (reduce $K[] as $k ({}; .[$k] = (if $p == null then -1 elif $reset then $c[$k] else $c[$k] - ($p[$k] // 0) end)))} ] as $src
      | (reduce $K[] as $k ({}; .[$k] = ([$src[].c[$k]] | add // 0))) as $tot
      | (reduce $K[] as $k ({}; .[$k] = (if $has then ([$src[].d[$k]] | add // 0) else -1 end))) as $dtot
      | (if $has then $dtot else $tot end) as $b
      | ($b.whitelisted > 0 and $b.reads >= $b.parsed + $b.unparsed + $b.whitelisted) as $disjointe
      | (if $disjointe then $b.parsed else $b.parsed - $b.whitelisted end) as $hors_lb
      | (if $disjointe then $b.parsed + $b.whitelisted else ([$b.parsed, $b.whitelisted] | max) end) as $an
      | (if $an > 0 then (($b.whitelisted * 100 / $an) | floor) else -1 end) as $part
      | (if ($src | length) == 0 then "aucune_source"
         elif ($has | not) then (if $tot.reads == 0 then "aucune_lecture"
                                 elif $tot.parsed == 0 and $tot.whitelisted == 0 then "aucune_analyse"
                                 else "premier_passage" end)
         elif $dtot.reads == 0 then "aucune_lecture"
         elif $dtot.parsed == 0 and $dtot.whitelisted == 0 then "aucune_analyse"
         else "lit" end) as $v0
      | { n: ($src | length), tot: $tot, dtot: $dtot, part: $part,
          reset: any($src[]; .reset),
          verdict: (if ($v0 == "lit" or $v0 == "premier_passage") | not then $v0
                    elif $b.whitelisted > 0 and $hors_lb <= 0 and $b.pour == 0 then "tout_en_liste_blanche"
                    elif $part >= $seuil then "surtout_liste_blanche"
                    else $v0 end),
          frozen: (if $has and $dtot.reads > 0 then [ $src[] | select(.d.reads == 0) | .source ][:100]
                   elif ($has | not) and $tot.reads > 0 then [ $src[] | select(.c.reads == 0) | .source ][:100]
                   else [] end),
          detail: [ $src[:100][] | {source} + .c + (.d | with_entries(.key += "_delta")) ],
          etat: (reduce $src[] as $x ({}; .[$x.source] = $x.c)) }' 2>/dev/null); then
    # Chaque morceau est RE-VALIDÉ avant d'entrer dans le battement : un `jq` qui rend 0 sans rien
    # écrire (bouchon, binaire tronqué) ne doit ni faire tomber le capteur sous `set -u` ni publier
    # un JSON cassé — c'est une lecture illisible, et elle se dit comme telle.
    _v=$(printf '%s' "$acq_out" | jq -r '.verdict' 2>/dev/null) || _v=''
    _s=$(printf '%s' "$acq_out" | jq -r '[.n, .tot.reads, .tot.parsed, .tot.unparsed, .tot.pour, .tot.whitelisted, .dtot.reads, .dtot.parsed, .dtot.unparsed, .dtot.pour, .dtot.whitelisted, .part, .reset] | map(tostring) | join(" ")' 2>/dev/null) || _s=''
    _fz=$(printf '%s' "$acq_out" | jq -c '.frozen' 2>/dev/null) || _fz=''
    _dt=$(printf '%s' "$acq_out" | jq -c '.detail' 2>/dev/null) || _dt=''
    _et=$(printf '%s' "$acq_out" | jq -c '.etat' 2>/dev/null) || _et=''
    _ok=1
    case "$_v" in lit|premier_passage|aucune_lecture|aucune_analyse|aucune_source|tout_en_liste_blanche|surtout_liste_blanche) ;; *) _ok=0 ;; esac
    case "$_fz" in \[*\]) ;; *) _ok=0 ;; esac
    case "$_dt" in \[*\]) ;; *) _ok=0 ;; esac
    case "$_et" in \{*\}) ;; *) _ok=0 ;; esac
    read -r _n _r _p _u _po _w _dr _dp _du _dpo _dw _pt _rs _reste <<EOF
$_s
EOF
    for _x in "${_n:-}" "${_r:-}" "${_p:-}" "${_u:-}" "${_po:-}" "${_w:-}" "${_dr:-}" "${_dp:-}" "${_du:-}" "${_dpo:-}" "${_dw:-}" "${_pt:-}"; do
      case "$_x" in ''|-|*[!0-9-]*|?*-*) _ok=0 ;; esac
    done
    case "${_rs:-}" in true|false) ;; *) _ok=0 ;; esac
    [ -z "${_reste:-}" ] || _ok=0
    if [ "$_ok" -eq 1 ]; then
      acq_verdict=$_v
      acq_n=$_n; acq_r=$_r; acq_p=$_p; acq_u=$_u; acq_po=$_po; acq_w=$_w
      acq_dr=$_dr; acq_dp=$_dp; acq_du=$_du; acq_dpo=$_dpo; acq_dw=$_dw; acq_reset=$_rs; acq_part=$_pt
      acq_frozen=$_fz; acq_detail=$_dt; acq_etat=$_et
      case "$acq_verdict" in
        aucune_source|aucune_lecture) acq_cause=source_absente ;;
        aucune_analyse|tout_en_liste_blanche) acq_cause=forme_inconnue ;;
      esac
    else
      acq_cause=forme_inconnue
    fi
  else
    acq_cause=forme_inconnue
  fi
fi
# ── 2 ter) QUELLE LISTE BLANCHE ÉCARTE (P10.32-k, prolongation). CONSTATÉ le 2026-11-04 : le verdict
# `tout_en_liste_blanche` peut être VRAI avec une cause affichée FAUSSE. Les lignes arrivées par un relais
# (adresse privée) partent bien dans `crowdsecurity/whitelists`, mais des sessions authentifiées arrivent avec
# leur adresse PUBLIQUE et partent dans une AUTRE liste blanche : le moteur lit alors les vraies adresses, et
# aucun trafic anonyme n'atteint l'origine (filtré en amont, par exemple par un CDN).
# LA FORME, LUE DANS LES SOURCES DE CROWDSEC (v1.6.8 et v1.7.0, `cmd/crowdsec-cli/climetrics/statwhitelist.go`
# et `store.go`), PAS DEVINÉE : `cscli metrics show whitelists -o json` rend `{"whitelists": {<nœud> : {<raison> :
# {"hits": n, "whitelisted": n}}}}`, tiré des compteurs `cs_node_wl_hits_total` / `cs_node_wl_hits_ok_total`
# (étiquettes `name` = nom du nœud de liste blanche, `reason`) ; `whitelisted` est le compteur même qui alimente
# `whitelisted` de l'acquisition. Repli : la section `whitelists` de `cscli metrics -o json`. v1.6.0 n'a pas
# cette section (`cmd/crowdsec-cli/metrics.go`) : la répartition y est INCONNUE, et dite telle.
# CE QUI N'EST PAS ÉTABLI : aucun `cscli` réel n'est joué ici (la garde le simule à cette forme) ; une liste
# d'autorisation centralisée (`cscli allowlists`, versions récentes) n'est pas comptée par ces compteurs, et on
# ne sait pas, d'après ces seules sources, si elle écarte des lignes avant les scénarios.
# MÊMES RÈGLES QUE L'ACQUISITION, contre `$STATE/crowdsec-whitelists.json` (nœud -> lignes écartées, toutes
# raisons) : compteur qui baisse = redémarrage (différence = valeur courante), nœud neuf à zéro, mis en attente
# avec l'état d'acquisition (donc même fenêtre), chaque morceau re-validé. Sans état lisible (premier passage,
# mise à niveau), la répartition porte sur les totaux depuis le démarrage de l'agent, et le dit. Sur un passage
# où l'acquisition avance mais où la répartition est illisible, l'état vaut `null` : le passage suivant repart
# des totaux plutôt que d'attribuer à la fenêtre des lignes d'avant elle.
# LA CAUSE MANDATAIRE n'est dite QUE si toutes les lignes écartées l'ont été par `crowdsecurity/whitelists` (la
# liste des adresses privées) ; une autre liste qui écarte des lignes prouve que des adresses réelles sont lues.
# Répartition illisible ou vide : « répartition inconnue », et la cause mandataire n'est pas affirmée.
# Le nom d'un nœud est ramené à `[A-Za-z0-9/_.:@-]` (le reste en `?`) et à 80 caractères ; dix nœuds au plus
# sont nommés, le reste compté. CE QUE CELA NE VOIT PAS : la répartition juge les totaux de toutes les sources,
# comme les verdicts.
WL_STATE="$STATE/crowdsec-whitelists.json"
TS_STATE="$STATE/crowdsec-scenarios-atteints.ts"
wl_total=-1; wl_prive=false; wl_base=''; wl_rep=''; wl_etat=null
if [ -n "$acq_etat" ]; then
  wl_raw=''
  if _x=$(cscli_agent metrics show whitelists -o json 2>/dev/null) && printf '%s' "$_x" | jq -e '(.whitelists | type) == "object"' >/dev/null 2>&1; then
    wl_raw=$_x
  elif _x=$(cscli_agent metrics -o json 2>/dev/null); then
    wl_raw=$_x
  fi
  wl_prev=null
  if [ -r "$WL_STATE" ]; then
    wl_prev=$(jq -c 'if type == "object" and all(.[]; type == "number") then . else null end' "$WL_STATE" 2>/dev/null) || wl_prev=null
    [ -n "$wl_prev" ] || wl_prev=null
  fi
  # shellcheck disable=SC2016
  if [ -n "$wl_raw" ] && wl_out=$(printf '%s' "$wl_raw" | jq -c --argjson prev "$wl_prev" '
      def n: if . == null then 0 elif type == "number" and . >= 0 then floor else error("compteur") end;
      if type != "object" or (.whitelists | type) != "object" then error("forme") else . end
      | [ .whitelists | to_entries[]
          | if (.value | type) != "object" then error("forme") else . end
          | {nom: .key, c: ([ .value[] | if type != "object" then error("forme") else (.whitelisted | n) end ] | add // 0)} ] as $l
      | ($prev | type == "object") as $has
      | [ $l[] | (if $has then $prev[.nom] else null end) as $p
          | . + {d: (if $p == null or .c < $p then .c else .c - $p end)} ] as $x
      | ([ $x[] | select(.d > 0) ] | sort_by(-.d, .nom)) as $nz
      | { total: ([ $nz[].d ] | add // 0),
          prive: (($nz | length) > 0 and all($nz[]; .nom == "crowdsecurity/whitelists")),
          base: (if $has then "fenetre" else "demarrage" end),
          rep: ([ $nz[:10][] | "\(.nom | gsub("[^A-Za-z0-9/_.:@-]"; "?") | .[:80]) : \(.d)" ] | join(", ")
                + (if ($nz | length) > 10 then ", +\(($nz | length) - 10) autre(s)" else "" end)),
          etat: (reduce $l[] as $e ({}; .[$e.nom] = $e.c)) }' 2>/dev/null); then
    _wt=$(printf '%s' "$wl_out" | jq -r '.total' 2>/dev/null) || _wt=''
    _wp=$(printf '%s' "$wl_out" | jq -r '.prive' 2>/dev/null) || _wp=''
    _wb=$(printf '%s' "$wl_out" | jq -r '.base' 2>/dev/null) || _wb=''
    _wr=$(printf '%s' "$wl_out" | jq -r '.rep' 2>/dev/null) || _wr=''
    _we=$(printf '%s' "$wl_out" | jq -c '.etat' 2>/dev/null) || _we=''
    _ok=1
    case "$_wt" in ''|*[!0-9]*) _ok=0 ;; esac
    case "$_wp" in true|false) ;; *) _ok=0 ;; esac
    case "$_wb" in fenetre|demarrage) ;; *) _ok=0 ;; esac
    case "$_wr" in *[!A-Za-z0-9/_.:@?,\ +\(\)-]*) _ok=0 ;; esac
    case "$_we" in \{*\}) ;; *) _ok=0 ;; esac
    if [ "$_ok" -eq 1 ]; then
      wl_total=$_wt; wl_prive=$_wp; wl_base=$_wb; wl_rep=$_wr; wl_etat=$_we
    fi
  fi
fi
# La cause, choisie sur la répartition : `mandataire`, `vraies_adresses` ou `repartition_inconnue`.
if [ "$wl_total" -gt 0 ] 2>/dev/null; then
  if [ "$wl_prive" = true ]; then cs_variante=mandataire; else cs_variante=vraies_adresses; fi
  if [ "$wl_base" = fenetre ]; then cs_rep_txt="répartition des lignes écartées sur la fenêtre : $wl_rep"; cs_rep_a="repartition des lignes ecartees sur la fenetre : $wl_rep"
  else cs_rep_txt="répartition des lignes écartées depuis le démarrage de l'agent : $wl_rep"; cs_rep_a="repartition des lignes ecartees depuis le demarrage de l'agent : $wl_rep"; fi
else
  cs_variante=repartition_inconnue; cs_rep_txt="répartition inconnue"; cs_rep_a="repartition inconnue"
fi
# ── 2 quater) DURÉE AU LIEU D'UN CRI PAR PASSAGE. `$TS_STATE` porte l'horodatage du dernier passage où l'état
# d'acquisition a AVANCÉ — donc où des lignes ont atteint les scénarios : il est mis en attente AVEC cet état.
# Un refus ne l'avance pas : la fenêtre court depuis ce passage-là. Absent ou illisible (mise à niveau, premier
# passage, horloge revenue en arrière), il est posé au passage qui le constate et la durée part de là, dite comme
# telle — elle peut être plus longue. Sous `PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES` : verdict
# `en_liste_blanche_sous_le_seuil`, NON refusant, l'état d'acquisition N'AVANCE PAS.
# HORODATAGE QUI NE PEUT PAS SE POSER (état non inscriptible) : la durée ne court jamais — elle repartirait de
# zéro à chaque passage et le refus ne partirait JAMAIS. Le verdict reste donc `tout_en_liste_blanche`
# (refus, sévérité 3, aveu), aussi sévère qu'avant le seuil, et la cause est dite ; l'échec d'écriture est avoué
# en plus (`etat/horodatage`).
cs_duree=-1; cs_duree_posee=0; cs_ts_ko=0; cs_duree_m="durée inconnue"; cs_duree_a="duree inconnue"
if [ "$acq_verdict" = tout_en_liste_blanche ]; then
  _t=$(cat "$TS_STATE" 2>/dev/null) || _t=''
  case "$_t" in ''|0?*|*[!0-9]*|?????????????*) _t='' ;; esac
  if [ -n "$_t" ] && [ "$_t" -le "$ts" ]; then
    cs_duree=$((ts - _t))
  else
    cs_duree=0; cs_duree_posee=1
    if _tt=$(mktemp "$STATE/.crowdsec-scenarios.XXXXXX" 2>/dev/null) && printf '%s' "$ts" > "$_tt"; then
      state_stage_file "$_tt" "$TS_STATE"
    else
      _cs_ko="$_cs_ko etat/horodatage"; cs_ts_ko=1
    fi
  fi
  if [ "$cs_ts_ko" -eq 0 ] && [ "$CS_SANS_SCEN_H" -gt 0 ] && [ "$cs_duree" -lt $((CS_SANS_SCEN_H * 3600)) ]; then
    acq_verdict=en_liste_blanche_sous_le_seuil
  fi
fi
if [ "$cs_duree" -ge 0 ]; then
  cs_duree_txt="$((cs_duree / 3600)) h $(printf '%02d' $(((cs_duree % 3600) / 60))) min"
  if [ "$cs_ts_ko" -eq 1 ]; then
    cs_duree_m="horodatage non inscriptible dans l'état du capteur : la durée sans ligne aux scénarios ne peut pas courir, refus sans attendre le seuil ($CS_SANS_SCEN_H h)"
    cs_duree_a="horodatage non inscriptible dans l'etat du capteur : la duree sans ligne aux scenarios ne peut pas courir, refus sans attendre le seuil ($CS_SANS_SCEN_H h)"
  elif [ "$cs_duree_posee" -eq 1 ]; then
    cs_duree_m="aucune ligne n'atteint les scénarios depuis ce passage (horodatage absent — mise à niveau ou premier passage — posé maintenant : la durée part d'ici, la durée réelle peut être plus longue), seuil $CS_SANS_SCEN_H h"
    cs_duree_a="aucune ligne aux scenarios depuis ce passage (horodatage absent, pose maintenant : la duree part d'ici et peut etre plus longue), seuil $CS_SANS_SCEN_H h"
  else
    cs_duree_m="aucune ligne n'atteint les scénarios depuis $cs_duree_txt, seuil $CS_SANS_SCEN_H h"
    cs_duree_a="aucune ligne aux scenarios depuis $cs_duree_txt, seuil $CS_SANS_SCEN_H h"
  fi
fi
case "$acq_verdict" in
  lit|premier_passage|surtout_liste_blanche)
    acq_refus=0
    # Un état qu'on ne peut pas poser ne coupe PAS le battement (son silence lèverait MUET) : il est avoué.
    # L'horodatage et la répartition sont mis en attente AVEC lui : même fenêtre, même passage.
    if acq_tmp=$(mktemp "$STATE/.crowdsec-acquisition.XXXXXX" 2>/dev/null) && printf '%s' "$acq_etat" > "$acq_tmp"; then
      state_stage_file "$acq_tmp" "$ACQ_STATE"
      if _tt=$(mktemp "$STATE/.crowdsec-scenarios.XXXXXX" 2>/dev/null) && printf '%s' "$ts" > "$_tt"; then
        state_stage_file "$_tt" "$TS_STATE"
      else
        _cs_ko="$_cs_ko etat/horodatage"
      fi
      if _wt=$(mktemp "$STATE/.crowdsec-whitelists.XXXXXX" 2>/dev/null) && printf '%s' "$wl_etat" > "$_wt"; then
        state_stage_file "$_wt" "$WL_STATE"
      else
        _cs_ko="$_cs_ko etat/listes-blanches"
      fi
    else
      _cs_ko="$_cs_ko etat/acquisition"
    fi ;;
  en_liste_blanche_sous_le_seuil) acq_refus=0 ;;
  *) acq_refus=1 ;;
esac
# âge de la dernière alerte (informatif, -1 si indéterminable / pas de `date -d`).
last_age=-1
last_created=$(printf '%s' "$raw" | jq -r '[ .[].created_at // empty ] | max // empty' 2>/dev/null || echo '')
if [ -n "$last_created" ]; then
  le=$(date -d "$last_created" +%s 2>/dev/null || echo '')
  [ -n "$le" ] && last_age=$((ts - le))
fi
ar=false; [ "$agent_ready" -eq 1 ] && ar=true
lo=false; [ "$lapi_ok" -eq 1 ] && lo=true
# sévérité : 0 (info) si sain ; 4 si scénarios cassés ; 3 si agent injoignable (transitoire possible -> le
# vrai « moteur mort » est attrapé par l'alerte MUET du collecteur CONTINU crowdsec-health).
if [ "$agent_ready" -eq 0 ]; then
  hsev=3; hmsg="CrowdSec INJOIGNABLE: agent non interrogeable"
elif [ "$scen_broken" -gt 0 ] 2>/dev/null; then
  hsev=4; hmsg="CrowdSec DÉGRADÉ: $scen_broken erreur(s) de chargement / $scen_loaded scénarios"
elif [ "$scen_broken" -lt 0 ] 2>/dev/null; then
  hsev=0; hmsg="CrowdSec santé: $scen_loaded scénarios (chargement inconnu — log agent inaccessible)"
else
  hsev=0; hmsg="CrowdSec santé: $scen_loaded scénarios, 0 erreur de chargement"
fi
# P10.32-g — un moteur qui ne lit rien ne prouve rien par son silence : la sévérité monte à 3 au moins.
# P10.32-k — les deux verdicts de liste blanche nomment la cause probable, que l'exploitant corrige à la
# source (faire lire à CrowdSec l'adresse du client, pas celle du relais).
# P10.32-k (prolongation) — la cause suit la répartition (2 ter) : mandataire seulement si TOUT part dans la liste
# des adresses privées.
case "$cs_variante" in
  mandataire)
    cs_cause_lb="cause probable : l'adresse cliente que CrowdSec lit est privée (celle d'un mandataire ou d'un tunnel) et la liste blanche des adresses privées l'écarte"
    cs_cause_a="cause probable : l'adresse cliente que CrowdSec lit est privee (celle d'un mandataire ou d'un tunnel) et la liste blanche des adresses privees l'ecarte" ;;
  vraies_adresses)
    cs_cause_lb="cause : le moteur lit les vraies adresses (une liste blanche autre que celle des adresses privées a écarté des lignes)"
    cs_cause_a="cause : le moteur lit les vraies adresses (une liste blanche autre que celle des adresses privees a ecarte des lignes)"
    # « rien d'anonyme n'a atteint l'origine » n'est vrai que si AUCUNE ligne n'a atteint les scénarios : sur
    # `surtout_liste_blanche`, des lignes hors liste blanche y sont parvenues, la phrase y serait fausse.
    case "$acq_verdict" in
      tout_en_liste_blanche|en_liste_blanche_sous_le_seuil)
        cs_cause_lb="$cs_cause_lb ; aucun trafic anonyme n'a atteint l'origine sur la fenêtre (filtré en amont, ou site injoignable)"
        cs_cause_a="$cs_cause_a ; aucun trafic anonyme n'a atteint l'origine sur la fenetre (filtre en amont, ou site injoignable)" ;;
    esac ;;
  *)
    cs_cause_lb="cause non établie : quelle liste blanche écarte les lignes n'a pas pu être lu"
    cs_cause_a="cause non etablie : quelle liste blanche ecarte les lignes n'a pas pu etre lu" ;;
esac
if [ "$acq_verdict" = tout_en_liste_blanche ]; then
  [ "$hsev" -lt 3 ] && hsev=3
  hmsg="$hmsg — ACQUISITION tout_en_liste_blanche : toutes les lignes analysées sont parties en liste blanche ($cs_rep_txt ; $cs_cause_lb), $cs_duree_m, l'absence d'alerte ne prouve rien"
elif [ "$acq_verdict" = en_liste_blanche_sous_le_seuil ]; then
  [ "$hsev" -lt 1 ] && hsev=1
  hmsg="$hmsg — acquisition en_liste_blanche_sous_le_seuil : toutes les lignes analysées sont parties en liste blanche ($cs_rep_txt ; $cs_cause_lb), $cs_duree_m ; refus de conclure au seuil"
elif [ "$acq_refus" -eq 1 ]; then
  [ "$hsev" -lt 3 ] && hsev=3
  hmsg="$hmsg — ACQUISITION $acq_verdict : aucune ligne n'atteint les scénarios, l'absence d'alerte ne prouve rien"
elif [ "$acq_verdict" = surtout_liste_blanche ]; then
  [ "$hsev" -lt 2 ] && hsev=2
  hmsg="$hmsg — ACQUISITION surtout_liste_blanche : $acq_part % des lignes analysées sont parties en liste blanche (seuil $CS_WL_SEUIL %, $cs_rep_txt ; $cs_cause_lb), la détection ne porte que sur le reste"
elif [ "$acq_part" -ge 0 ] 2>/dev/null; then
  hmsg="$hmsg — liste blanche : $acq_part % des lignes analysées"
fi
hfields="{\"scenarios_loaded\":$scen_loaded,\"scenarios_broken\":$scen_broken,\"agent_ready\":$ar,\"lapi_ok\":$lo,\"last_alert_age_s\":$last_age,\"acq_verdict\":\"$acq_verdict\",\"acq_sources\":$acq_n,\"acq_reads\":$acq_r,\"acq_parsed\":$acq_p,\"acq_unparsed\":$acq_u,\"acq_pour\":$acq_po,\"acq_whitelisted\":$acq_w,\"acq_reads_delta\":$acq_dr,\"acq_parsed_delta\":$acq_dp,\"acq_unparsed_delta\":$acq_du,\"acq_pour_delta\":$acq_dpo,\"acq_whitelisted_delta\":$acq_dw,\"acq_counters_reset\":$acq_reset,\"acq_frozen_sources\":$acq_frozen,\"acquisition\":$acq_detail}"
# PAS de dedup (event.dedup est UNIQUE) -> chaque battement S'INSÈRE -> MAX(ts) avance -> heartbeat vivant.
events="$events${events:+,}$(heartbeat crowdsec "$hmsg" "$hfields" "$hsev")"

# S36 — L'AVEU PART PAR LE CANAL DEJA LIVRE, ET APRES le battement : le battement doit partir quoi
# qu'il arrive (son silence leve l'alerte MUET du capteur CONTINU), l'aveu s'y ajoute sans le
# remplacer. `plume_lecture_partielle` n'ecrit ni ne jette aucun marqueur — le seul de ce capteur,
# `crowdsec-acquisition.json` (P10.32-g), n'est mis en attente que sur une acquisition lue — elle
# nomme la lecture ratee, et `de-collector-unavailable` (severite 2) alerte dessus.
if [ -n "$_cs_ko" ]; then
  plume_lecture_partielle crowdsec source_illisible "lecture(s) CrowdSec en echec ce passage :$_cs_ko. Les alertes et l'etat du moteur de cette portee ne sont PAS observes ; l'absence d'attaque ne peut PAS en etre conclue."
fi
# P10.32-g — aveu DISTINCT (cause propre, donc enveloppe propre) : ce que le moteur LIT n'est pas établi.
# LA CLÉ DE DÉDOUBLONNAGE NE PORTE PAS LES COMPTES. Le détail en porte (lignes lues, analysées) et,
# l'état n'avançant pas sur un refus, `aucune_analyse` voit ses lignes lues GRANDIR à chaque passage :
# une clé prise sur le détail changerait à chaque passage et la dédup horaire ne tiendrait plus (une
# alerte de couverture par passage). La matière de la clé est donc le verdict, la cause et, pour
# `tout_en_liste_blanche`, la variante de cause (`mandataire`, `vraies_adresses`, `repartition_inconnue`,
# P10.32-k) : une cause qui CHANGE dans l'heure est un fait neuf, un nouvel aveu ; ni la durée ni les
# comptes n'y entrent. Le central garde le détail du PREMIER aveu de l'heure, le battement porte les
# comptes du passage.
if [ "$acq_verdict" = tout_en_liste_blanche ]; then
  plume_lecture_partielle crowdsec "$acq_cause" "acquisition CrowdSec : tout_en_liste_blanche (sources : $acq_n, lignes analysees : $( [ "$acq_dp" -ge 0 ] && echo "$acq_dp" || echo "$acq_p"), en liste blanche : $( [ "$acq_dw" -ge 0 ] && echo "$acq_dw" || echo "$acq_w"), versees aux scenarios : 0 ; $cs_rep_a). Toutes les lignes analysees sont ecartees par une liste blanche ; $cs_cause_a. $cs_duree_a ; l'absence d'alerte ne peut PAS etre conclue." \
    "crowdsec acquisition $acq_verdict $acq_cause $cs_variante"
elif [ "$acq_refus" -eq 1 ]; then
  plume_lecture_partielle crowdsec "$acq_cause" "acquisition CrowdSec : $acq_verdict (sources : $acq_n, lignes lues depuis le passage precedent : $acq_dr, analysees : $acq_dp). Aucune ligne n'atteint les scenarios ; l'absence d'alerte ne peut PAS etre conclue." \
    "crowdsec acquisition $acq_verdict $acq_cause"
fi

# ── 3) SHIP : un seul spool par run (alertes éventuelles + battement de santé TOUJOURS présent).
[ -z "$events" ] && plume_exit_nodata
spool_write_then_ack "crowdsec-$ts.json" "$(emit_event "$events")"
