#!/usr/bin/env python3
"""Le répondeur de l'hôte applique la durée de ban SERVIE par le central — garde de CI (`P11.25-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`collectors/respond.sh` lisait la file d'actions par `curl -sS` SANS juger le statut : le corps d'un 503
(ou de tout non-200) était parsé comme une liste, et une ligne qui y commençait par un chiffre devenait une
action exécutée en root. Et la durée d'un ban était toujours celle de l'hôte (`-d $PLUME_BAN_DURATION`),
jamais celle du playbook que le central sert depuis la vague BT (`ban_ttl_s`, forme JSON par ligne).

LE CONTRAT EST RELU DANS LA BASE, PAS RECOPIÉ
--------------------------------------------
Le type de contenu demandé (`TYPE_DE_LA_FILE_JSON_PAR_LIGNE`, daemon/src/handlers/actions.rs) et la borne de
la durée (`BAN_TTL_MAX_S`, daemon/src/auth.rs) sont LUS dans l'arbre du démon et exigés tels quels dans le
répondeur livré : un démon qui change l'un sans le répondeur fait rougir cette garde.

CE QUI EST JOUÉ
---------------
Le script LIVRÉ, sous `sh`, dans un `PATH` fabriqué : utilitaires POSIX, le VRAI `curl`, `jq` et/ou `python3`
selon le scénario (le lecteur JSON est un choix du script, pas du banc), et des bouchons `cscli`, `nft`,
`fail2ban-client` qui enregistrent leurs arguments sans rien appliquer. En face, un faux central local
(`http.server`, 127.0.0.1) qui se comporte comme le démon (JSON par ligne si et seulement si l'en-tête le
demande), ou comme un central antérieur (TSV toujours), ou rend un statut d'échec. Adresses RFC 5737 seules.
Le corps d'une remise y est lu comme le démon le lit (`corps_lu_comme_le_demon` : UTF-8 valide, JSON strict) ; un
corps que le démon refuserait reçoit le même 400, et le scénario rougit (`REMISES_REFUSEES`) — aucun scénario n'a
besoin d'un corps invalide. Chaque refus de ce lecteur a son épreuve (`CORPS_D_EPREUVE`), jouée à chaque exécution ;
le jugement de `REMISES_REFUSEES` a la sienne (mutant `remit_body_keeps_raw_line_breaks`).

ÉPREUVE DES MUTANTS, JOUÉE À CHAQUE EXÉCUTION (`--sans-mutants` la saute, pour itérer) : chaque mutant nommé de `MUTANTS` est posé sur une COPIE temporaire du
script (l'arbre n'est jamais touché) et doit faire rougir AU MOINS les scénarios qu'il nomme ; un motif de
mutant absent du script est une garde périmée, et c'est un échec.

UN BAN PLUS COURT NE RACCOURCIT JAMAIS UN BAN EN COURS (voie nft) : le bouchon `nft` rend les sorties MESURÉES sur
un nft réel (pose exclusive refusée, `get element` présent ou absent, `expires` sous ses formes) ; sont tenus la
conservation (aucune commande qui récrit), l'allongement en UNE transaction `nft -f -`, la pose simple d'une adresse
absente, l'élément SANS FIN (ni `timeout` ni `expires`) conservé avec sa propre phrase, le reste illisible qui ne
récrit rien et rend `failed` avec sa phrase, chaque forme d'`expires` jugée à son bord, la reprise unique après une
expiration, le dry-run qui ne promet qu'un allongement, la lecture des erreurs de nft sous une locale traduite
(`LC_ALL=C` posé sur chaque appel), et la garde de durée qui refuse une unité répétée ou désordonnée avec sa cause
— à l'exécution comme au plan nft — sans refuser une forme mesurée acceptée par nft ; le plan cscli nomme la
commande que cscli joue réellement, jamais un refus que seule la règle de nft prononcerait.

LA LEVÉE nft SUIT LA RÈGLE DU DÉMON (`classer_le_retrait_nft`, `verdict_des_deux_retraits_nft`, daemon/src/handlers/
actions.rs) : le bouchon fixe l'issue de chaque `delete element` par set et par adresse (`NFT_RETRAITS`). Sont tenus,
résultat remis comparé ENTIER : un refus sur le premier set, sur le second, sur les deux -> `failed` qui nomme le set,
le code et ce que nft a écrit ; absent d'un set et retiré de l'autre, dans les deux ordres -> `done`, texte d'avant ;
nft seul sans aucun retrait (deux absences, ou une absence sans set à durée) -> `failed`, LEVEE NON FAITE ; un nft tué
par un signal après avoir écrit l'absence -> refus dit avec le signal ; les bords de code 125 (absente), 126, 127, 128
et 129 (refus, le dernier dit interrompu par le signal 1) ; un refus avec fail2ban présent -> `failed` ; DÉCISION :
nft sans retrait avec fail2ban ou CrowdSec présent -> `done` comme avant (leurs codes ne sont pas mesurés) ; l'absence
écrite sur la sortie STANDARD n'est pas une absence, et cette sortie atteint le journal ; l'absence reconnue sous une
locale traduite (`LC_ALL=C` posé sur le retrait) ; une sortie de refus longue et sur plusieurs lignes mise sur une
ligne, chaque caractère de contrôle en espace, coupée sur un caractère à la borne, la coupe dite ; table absente ou set
à durée absent (absence mesurée, lue sous `LC_ALL=C` même sous une locale traduite) : rien n'est tenté sur ce qui
n'existe pas ; une SONDE refusée n'est pas une absence : le retrait est tenté et son classement tranche, la sonde
refusée dite au journal ; nft absent de l'hôte : ni sondé ni tenté ; un échec MUET (code non nul, sortie d'erreur
vide) est un refus, au retrait (`failed`) comme à la sonde (le retrait tranche) ; une sonde tuée par un signal APRÈS avoir
écrit l'absence, sortie en code 126, ou qui n'écrit l'absence que sur sa sortie STANDARD est une sonde refusée (son
code est lu, sa sortie standard jetée) ; l'état du verdict est remis à zéro à chaque levée d'un même tour (le refus ou
le retrait d'une levée ne reste pas acquis à la suivante) ; le séparateur d'unité \x1f, haut de la plage des caractères
de contrôle, devient une espace comme les autres. Mutants `unban_*` et
`nft_unban_leaves_the_ttl_set` de `MUTANTS`, chacun rouge sur ses scénarios.

`P10.21-n` — UNE RIPOSTE RE-SERVIE N'EST JAMAIS EXÉCUTÉE UNE SECONDE FOIS À L'AVEUGLE : plusieurs tours sur un même
répertoire d'état, le nombre d'appels au faux nft (ou cscli) compté EXACTEMENT à chaque tour, le verdict remis comparé à
l'octet. Arrêt brutal simulé par un bouchon qui tue le groupe du script (`NFT_TUER_SUR`, ou un curl qui tue à la remise),
le script tournant dans sa propre session. Sont tenus : les cinq chemins qui réexécutaient (2a arrêt entre l'exécution et
le verdict, ban et levée, avant la remise -> re-remise sans appel, pendant l'exécution -> reprise dite, levée constatée
absente rendue `done`, refus de retrait resté `failed` ; 2b état non inscriptible -> exécutée quand même et avouée,
file de rejeu pleine, écriture du rejeu refusée ; 2c refus définitif, rejeu abandonné), la fin de chaque aveu de verdict
non retenu (réexécutée ou non, lue dans le registre), la borne du registre aux trois bords, l'éviction de la plus
ancienne `faite` jamais d'une `commencee` (tout ou rien), les lignes illisibles écartées et dites, une queue d'octets
nuls, le simulacre et chaque refus d'avant exécution qui n'écrivent rien, le verdict enregistré re-remis tel quel avant
tout contrôle, l'entrée retirée sur 2xx, sur `"ok":false` et au rejeu remis, gardée sur 503 et sur refus définitif,
l'identifiant réutilisé pour une autre riposte, l'identifiant trop long, la ligne bornée (cible, résultat coupé sur un
caractère entier, sans caractère de contrôle), chaque écriture refusée et le registre illisible ; le verrou : deux
exécutions simultanées (une seule traite, `flock` et repli `mkdir`), porteur vivant respecté, écrit en retard relu,
verrou orphelin repris (mort, pid recyclé, jamais écrit) puis TENU pendant le tour, une seconde exécution qui ne
rejoue pas la file de rejeu, `flock` libre après un arrêt brutal, verrou impossible -> le tour continue et le dit ;
et le bord de l'identifiant (13 et 130 au registre : retrait et lecture de l'id exact), le mode 0600 du registre
après l'ajout et après la republication, l'entrée gardée quand le REJEU est refusé, le ban repris refusé après une
levée vaine du même tour resté `failed`, l'aveu qui ignore une ligne illisible restée au registre, la sortie sur mktemp refusé qui rend le verrou du repli,
une exécution sortie au verrou qui ne touche pas au registre, la forme du registre ancrée en fin de ligne. Mutants listés après la marque `P10.21-n` de `MUTANTS`, chacun rouge sur ses scénarios.
Deux scénarios (ajout refusé, lecture refusée, repli bloqué) exigent un utilisateur non privilégié : sous root, la garde
refuse de conclure (code 2). `--scenarios=a,b` et `--mutants=x,y` jouent une partie, et le disent.

CE QUE CETTE GARDE NE TIENT PAS : un vrai CrowdSec, un vrai nft (noyau, borne du timeout) ou un vrai fail2ban
ne sont pas exercés (l'absence d'instant sans ban pendant un allongement se prouve sur un vrai nft, hors CI) — en particulier, qu'un `timeout 0s` donne un élément sans fin n'est pas mesuré sur un
nft réel : le répondeur refuse la durée nulle, et c'est ce refus qui est tenu ici ; le rejeu des verdicts et la liste d'épargne ont leurs propres gardes
(`check_enforcer_lists_fail_closed.py`), qui jouent le chemin TSV.
"""
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

RACINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPT = os.path.join(RACINE, "collectors", "respond.sh")

# Un tour normal finit en quelques secondes ; au-delà, le script boucle (mutant `retry_unbounded`).
DELAI_D_UN_TOUR_S = 60

OUTILS = ["cat", "sed", "tr", "grep", "date", "mkdir", "touch", "mktemp", "chmod", "mv", "rm", "dd", "cut",
          "wc", "sleep", "curl", "awk"]

BOUCHON = r"""#!/bin/sh
printf '%s\n' "$*" >> "$TRACE_ENFORCEMENT.NOM"
exit 0
"""
# nft : l'état de l'hôte est fixé par NFT_ETAT —
#   `ancien` (défaut) : la table `inet plume` existe (version antérieure), le set à durée NON ;
#   `neuf`            : ni table ni set (hôte jamais équipé) ;
#   `equipe`          : table ET set à durée déjà là (hôte équipé par cette version).
# `P11.25-a` — LES ADRESSES DÉJÀ BANNIES dans `blocklist_ttl` : NFT_PRESENTS="<ip>=<mode> ...". Les sorties sont
# celles MESURÉES sur nft 1.1.7 (noyau 7.2, espace de noms réseau sans privilège) : `create element` sur une
# adresse présente rend « Error: Could not process rule: File exists » (code 1) ; `get element` sur une adresse
# absente rend « Error: Could not process rule: No such file or directory » (code 1) ; sur une adresse présente,
# la table avec `elements = { <ip> timeout <t> expires <reste> }`. Modes :
#   reste:<forme>           `get` rend cette liste, `expires <forme>` ;
#   sans_fin                `get` rend l'élément sans `timeout` ni `expires` (élément posé sans délai : forme mesurée) ;
#   timeout_sans_expires    `get` rend l'élément avec `timeout` mais sans `expires` (champ d'expiration illisible) ;
#   sortie_inconnue         `get` réussit mais ne nomme pas l'adresse ;
#   en_double               `get` nomme l'adresse deux fois ;
#   expire_a_la_lecture     `get` rend l'absence ET l'élément expire (la pose exclusive suivante réussit) ;
#   absent_a_chaque_lecture `get` rend l'absence, la pose exclusive échoue toujours (course répétée) ;
#   lecture_refusee         `get` échoue autrement (nft sans `get element` : erreur de syntaxe).
# NFT_CREATE_REFUS="<ip> ..." : `create element` sur ces adresses est refusé pour une AUTRE cause que leur présence
# (« Operation not permitted », code 1 — droit refusé ; même forme que l'ensemble absent ou un délai refusé).
# `nft -f -` (transaction) écrit chaque ligne lue sur l'entrée standard dans la trace, préfixée `TX| `.
# LOCALE : nft cite le texte de `strerror`, que la glibc TRADUIT selon la locale. Hors locale C (LC_ALL, sinon
# LC_MESSAGES, sinon LANG), le bouchon rend « File exists » et « No such file or directory » traduits, comme un hôte
# en français : le répondeur ne les reconnaît que parce qu'il pose `LC_ALL=C` sur chaque appel qui les lit.
# NFT_TX : `ok` (défaut) ; `expiree:<ip>` (l'élément expire avant la transaction : absence, code 1) ;
# `refus` (« Device or resource busy », code 1).
# `P11.25-a` — LA LEVÉE : NFT_RETRAITS="<set>:<ip>=<mode> ..." fixe l'issue de `delete element` sur ce set pour cette
# adresse (défaut : retirée, code 0, rien d'écrit) :
#   absent         l'absence MESURÉE (« No such file or directory », traduite hors locale C, code 1) ;
#   refus          « Operation not permitted » (droit refusé), code 1 ;
#   signal         écrit l'absence sur la sortie d'erreur, PUIS se tue par SIGKILL (code 137 vu du script) ;
#   stdout_absent  écrit l'absence sur la sortie STANDARD et « Device or resource busy » sur la sortie d'erreur, code 1 ;
#   bavard         refus dont la sortie d'erreur porte NFT_BAVARD après le message, code 1 ;
#   absent_code:<n> écrit l'absence sur la sortie d'erreur et sort avec le code <n> (bords 125 à 129) ;
#   muet           sort en code 1 SANS RIEN ÉCRIRE (échec muet).
# Les SONDES `list table inet plume` et `list set inet plume blocklist_ttl` : un objet absent (NFT_ETAT `neuf`, ou
# `ancien` pour le set à durée) écrit l'absence MESURÉE (« No such file or directory », traduite hors locale C) et sort
# en code 1 ; NFT_SONDES_REFUSEES="table set" (l'un, l'autre ou les deux) rend la sonde REFUSÉE (« Operation not
# permitted », code 1), que l'objet existe ou non. NFT_SONDE_TABLE=<mode> et NFT_SONDE_SET=<mode> fixent l'issue de la
# sonde de table, de set à durée, quel que soit l'état de l'hôte (défaut : aucun mode, l'état décide) :
#   muet           sort en code 1 SANS RIEN ÉCRIRE ;
#   stdout         écrit l'absence sur la sortie STANDARD seule et « Device or resource busy » sur la sortie d'erreur, code 1 ;
#   signal         écrit l'absence sur la sortie d'erreur, PUIS se tue par SIGKILL (code 137 vu du script) ;
#   code126        écrit l'absence sur la sortie d'erreur et sort en code 126 (commande qui ne part pas).
# `P10.21-n` — NFT_TUER_SUR=<motif> : la commande qui correspond est TRACÉE (son effet est tenu pour acquis), puis le
# bouchon tue tout le groupe du script (`kill -9 0`) : l'agent s'arrête brutalement au milieu de l'exécution, avant que
# rien d'autre ne soit écrit. NFT_ATTENDRE_SUR=<motif> : la commande qui correspond pose `$NFT_ATTENDRE.arrive`, puis
# attend que `$NFT_ATTENDRE` existe — l'exécution reste en cours, verrou tenu, le temps qu'une seconde exécution joue.
BOUCHON_NFT = r"""#!/bin/sh
printf '%s\n' "$*" >> "$TRACE_ENFORCEMENT.nft"
case "$*" in ${NFT_TUER_SUR:-__jamais__}) kill -9 0 ;; esac
case "$*" in ${NFT_ATTENDRE_SUR:-__jamais__})
  : > "$NFT_ATTENDRE.arrive"; while [ ! -e "$NFT_ATTENDRE" ]; do sleep 0.1; done ;;
esac
case "${LC_ALL:-${LC_MESSAGES:-${LANG:-C}}}" in
  C|POSIX|C.*) ENOENT='No such file or directory'; EEXIST='File exists' ;;
  *) ENOENT='Aucun fichier ou dossier de ce type'; EEXIST='Le fichier existe' ;;
esac
refus_de_sonde() { printf 'Error: Could not process rule: Operation not permitted\n%s\n' "$*" >&2; exit 1; }
case "$*" in
  "list table inet plume") case " ${NFT_SONDES_REFUSEES:-} " in *" table "*) refus_de_sonde "$*" ;; esac ;;
  "list set inet plume blocklist_ttl") case " ${NFT_SONDES_REFUSEES:-} " in *" set "*) refus_de_sonde "$*" ;; esac ;;
esac
sonde_selon() {
  case "$1" in
    muet) exit 1 ;;
    stdout) printf 'Error: %s\n%s\n' "$ENOENT" "$2"; printf 'Error: Could not process rule: Device or resource busy\n' >&2; exit 1 ;;
    signal) printf 'Error: %s\n%s\n' "$ENOENT" "$2" >&2; kill -9 $$ ;;
    code126) printf 'Error: %s\n%s\n' "$ENOENT" "$2" >&2; exit 126 ;;
  esac
}
case "$*" in
  "list table inet plume") sonde_selon "${NFT_SONDE_TABLE:-}" "$*" ;;
  "list set inet plume blocklist_ttl") sonde_selon "${NFT_SONDE_SET:-}" "$*" ;;
esac
absence_d_objet() { printf 'Error: %s\n%s\n' "$ENOENT" "$1" >&2; exit 1; }
case "${NFT_ETAT:-ancien}:$*" in
  "ancien:list set inet plume blocklist_ttl") absence_d_objet "$*" ;;
  "neuf:list table inet plume"|"neuf:list set inet plume blocklist_ttl") absence_d_objet "$*" ;;
esac
mode_de() {
  for e in ${NFT_PRESENTS:-}; do
    case "$e" in "$1="*) [ -e "$TRACE_ENFORCEMENT.nft.expiree.$1" ] && return 1; printf '%s' "${e#*=}"; return 0 ;; esac
  done
  return 1
}
cible() { x=${1#"{ "}; printf '%s' "${x%% *}"; }
absence() { printf 'Error: Could not process rule: %s\n%s\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n' "$ENOENT" "$1" >&2; exit 1; }
case "$1 $2" in
  "create element")
    ip=$(cible "$6")
    case " ${NFT_CREATE_REFUS:-} " in
      *" $ip "*) printf 'Error: Could not process rule: Operation not permitted\n%s\n' "$*" >&2; exit 1 ;;
    esac
    if mode_de "$ip" >/dev/null; then
      printf 'Error: Could not process rule: %s\n%s\n                                          ^^^^^^^^^^^\n' "$EEXIST" "$*" >&2
      exit 1
    fi
    exit 0 ;;
  "get element")
    ip=$(cible "$6")
    m=$(mode_de "$ip") || absence "$*"
    entete='table inet plume {\n\tset blocklist_ttl {\n\t\ttype ipv4_addr\n\t\tflags timeout\n'
    case "$m" in
      reste:*) printf "$entete"'\t\telements = { %s timeout 10m expires %s }\n\t}\n}\n' "$ip" "${m#reste:}" ;;
      sans_fin) printf "$entete"'\t\telements = { %s }\n\t}\n}\n' "$ip" ;;
      timeout_sans_expires) printf "$entete"'\t\telements = { %s timeout 10m }\n\t}\n}\n' "$ip" ;;
      sortie_inconnue) printf "$entete"'\t}\n}\n' ;;
      en_double) printf "$entete"'\t\telements = { %s timeout 10m expires 9m59s990ms, %s timeout 10m expires 9m59s990ms }\n\t}\n}\n' "$ip" "$ip" ;;
      expire_a_la_lecture) : > "$TRACE_ENFORCEMENT.nft.expiree.$ip"; absence "$*" ;;
      absent_a_chaque_lecture) absence "$*" ;;
      lecture_refusee) printf 'Error: syntax error, unexpected get\n%s\n^^^\n' "$*" >&2; exit 1 ;;
    esac
    exit 0 ;;
  "delete element")
    ip=$(cible "$6"); m=retiree
    for e in ${NFT_RETRAITS:-}; do case "$e" in "$5:$ip="*) m=${e#*=} ;; esac; done
    case "$m" in
      absent) absence "$*" ;;
      refus) printf 'Error: Could not process rule: Operation not permitted\n%s\n' "$*" >&2; exit 1 ;;
      signal) printf 'Error: Could not process rule: %s\n' "$ENOENT" >&2; kill -9 $$ ;;
      stdout_absent) printf 'Error: Could not process rule: %s\n' "$ENOENT"
                     printf 'Error: Could not process rule: Device or resource busy\n' >&2; exit 1 ;;
      bavard) printf 'Error: Could not process rule: Operation not permitted %s\n' "$NFT_BAVARD" >&2; exit 1 ;;
      absent_code:*) printf 'Error: Could not process rule: %s\n' "$ENOENT" >&2; exit "${m#absent_code:}" ;;
      muet) exit 1 ;;
    esac
    exit 0 ;;
  "-f -")
    while IFS= read -r l; do printf 'TX| %s\n' "$l" >> "$TRACE_ENFORCEMENT.nft"; done
    case "${NFT_TX:-ok}" in
      expiree:*) : > "$TRACE_ENFORCEMENT.nft.expiree.${NFT_TX#expiree:}"
                 printf '/dev/stdin:1:43-53: Error: Could not process rule: %s\n' "$ENOENT" >&2; exit 1 ;;
      refus) printf '/dev/stdin:2:40-50: Error: Could not process rule: Device or resource busy\n' >&2; exit 1 ;;
    esac
    exit 0 ;;
esac
exit 0
"""


# Toute commande nft qui pose ou retire un élément, transaction comprise (`-f -`, lignes `TX| `).
POSE_NFT = re.compile(r"^(TX\| )?(add|create|delete) element|^-f -$", re.M)


def refuser_de_conclure(msg):
    """Rien n'a été mesuré : code 2, distinct d'une propriété violée (1)."""
    print(f"::error::{msg}")
    sys.exit(2)


def contrat_du_demon():
    actions = open(os.path.join(RACINE, "daemon/src/handlers/actions.rs"), encoding="utf-8").read()
    auth = open(os.path.join(RACINE, "daemon/src/auth.rs"), encoding="utf-8").read()
    m = re.search(r'const TYPE_DE_LA_FILE_JSON_PAR_LIGNE: &str = "([^"]+)";', actions)
    b = re.search(r"const BAN_TTL_MAX_S: i64 = (\d+) \* (\d+);", auth)
    if not m or not b:
        refuser_de_conclure("contrat du démon introuvable (TYPE_DE_LA_FILE_JSON_PAR_LIGNE / BAN_TTL_MAX_S) : "
                         "la garde refuse de conclure")
    return m.group(1), int(b.group(1)) * int(b.group(2))


TYPE_JSON, BORNE = contrat_du_demon()

# Remises que le faux central a refusées pendant le scénario en cours (vidée et jugée par `jouer_tout`).
REMISES_REFUSEES = []


def corps_lu_comme_le_demon(octets):
    """Le corps d'une remise lu comme le démon le lit (`Json<Value>` d'axum 0.8, `serde_json::from_slice`) : UTF-8
    valide, JSON strict — aucun caractère de contrôle brut dans une chaîne, rien après la valeur, ni `NaN` ni
    `Infinity`, aucune moitié de paire de substitution échappée seule. Rend la valeur, ou lève ValueError là où le
    démon rendrait un 400. Chaque refus a son épreuve dans `epreuve_du_lecteur_du_faux_central`."""
    texte = octets.decode("utf-8")  # UnicodeDecodeError est un ValueError

    def constante_refusee(nom):
        raise ValueError(f"constante {nom} hors JSON")

    valeur = json.loads(texte, parse_constant=constante_refusee)
    pile = [valeur]
    while pile:
        x = pile.pop()
        if isinstance(x, str):
            x.encode("utf-8")  # UnicodeEncodeError (un ValueError) sur une moitié de paire seule
        elif isinstance(x, dict):
            pile.extend(x.keys())
            pile.extend(x.values())
        elif isinstance(x, list):
            pile.extend(x)
    return valeur


# (corps, admis) — chaque refus de `corps_lu_comme_le_demon` a le sien, et le corps admis prouve qu'il n'en refuse pas
# trop : un lecteur relâché (`strict=False`, `errors="replace"`, sans `parse_constant`, sans le contrôle des moitiés de
# paire) laisse passer au moins une ligne `False`.
CORPS_D_EPREUVE = [
    ('{"id":1,"status":"done","result":"été | ok"}'.encode("utf-8"), True),
    (b'{"id":1,"status":"done","result":"a\nb"}', False),
    (b'{"id":1,"status":"done","result":"a\tb"}', False),
    (b'{"id":1,"status":"done","result":"a\x01b"}', False),
    (b'{"id":1,"status":"done","result":"coupe \xc3"}', False),
    (b'{"id":1,"status":"done","result":"\xff"}', False),
    (b'{"id":1,"status":"done","result":"ok"} x', False),
    (b'{"id":NaN,"status":"done","result":"ok"}', False),
    (b'{"id":1,"status":"done","result":"\\ud800"}', False),
    (b'{"id":1,"status":"done","\\udc00":"ok"}', False),
    (b'{"id":1,"status":"done","result":"ok","l":[["\\udbff"]]}', False),
]


def epreuve_du_lecteur_du_faux_central():
    fautes = []
    for corps, admis in CORPS_D_EPREUVE:
        try:
            corps_lu_comme_le_demon(corps)
            lu = True
        except ValueError:
            lu = False
        exiger(fautes, lu == admis, f"faux central : {corps!r} {'refusé' if admis else 'ADMIS'}, le démon "
                                    f"{'le lit' if admis else 'le refuse (400)'}")
    return fautes


class Central:
    """Faux central. mode : 'demon' (JSON par ligne ssi Accept le nomme), 'tsv' (central antérieur),
    'statut' (statut, type, corps fixés). Journalise les en-têtes Accept et les verdicts remis."""

    def __init__(self, mode, actions=(), lignes_json=None, statut=None, type_contenu=None, corps=None,
                 longueur_annoncee=None, statut_remise=200, statuts_remise=(), corps_remise='{"ok":true}'):
        self.mode, self.actions, self.lignes_json = mode, list(actions), lignes_json
        self.statut, self.type_contenu, self.corps = statut, type_contenu, corps
        # longueur_annoncee : Content-Length MENTI (plus grand que le corps) => transfert tronqué côté curl.
        self.longueur_annoncee, self.statut_remise = longueur_annoncee, statut_remise
        # `P10.21-n` : statuts des remises dans l'ordre (puis `statut_remise`), et corps rendu à chaque remise.
        self.statuts_remise, self.corps_remise = list(statuts_remise), corps_remise
        self.accepts, self.verdicts, self.corps_remis = [], [], []
        central = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                central.accepts.append(self.headers.get("Accept"))
                st, ty, co = central.reponse(self.headers.get("Accept") or "")
                self.send_response(st)
                self.send_header("Content-Type", ty)
                self.send_header("Content-Length", str(central.longueur_annoncee or len(co)))
                self.end_headers()
                self.wfile.write(co)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                octets = self.rfile.read(n)
                try:
                    verdict = corps_lu_comme_le_demon(octets)
                except ValueError as e:
                    # Le démon refuserait ce corps (400 d'axum) : refusé ici de même, et compté pour le scénario.
                    REMISES_REFUSEES.append(f"{e} : {octets[:160]!r}")
                    co = b"Failed to parse the request body as JSON"
                    self.send_response(400)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(co)))
                    self.end_headers()
                    self.wfile.write(co)
                    return
                central.corps_remis.append(octets.decode("utf-8"))
                central.verdicts.append(verdict)
                co = central.corps_remise.encode()
                st = central.statuts_remise.pop(0) if central.statuts_remise else central.statut_remise
                self.send_response(st)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(co)))
                self.end_headers()
                self.wfile.write(co)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tsv(self):
        return "".join(f"{a['id']}\t{a['kind']}\t{a['target']}\t{1 if a['dry_run'] else 0}\n" for a in self.actions)

    def ndjson(self):
        if self.lignes_json is not None:
            return "".join(l + "\n" for l in self.lignes_json)
        return "".join(json.dumps(a, separators=(",", ":")) + "\n" for a in self.actions)

    def reponse(self, accept):
        if self.mode == "statut":
            return self.statut, self.type_contenu, self.corps.encode()
        demande = any(t.split(";")[0].strip().lower() == TYPE_JSON and "q=0" not in t.replace(" ", "")
                      for t in accept.split(","))
        if self.mode == "demon" and demande:
            return 200, self.type_contenu or TYPE_JSON, self.ndjson().encode()
        return 200, "text/plain; charset=utf-8", self.tsv().encode()

    def fermer(self):
        self.srv.shutdown()
        self.srv.server_close()


def ban(i, cible, ttl=None, dry=False, **plus):
    a = {"id": i, "kind": "ban_ip", "target": cible, "dry_run": dry}
    if ttl is not None:
        a["ban_ttl_s"] = ttl
    a.update(plus)
    return a


def unban(i, cible):
    return {"id": i, "kind": "unban_ip", "target": cible, "dry_run": False}


class Tour:
    def __init__(self, rc, stderr, verdicts, accepts, traces, tmp):
        self.rc, self.stderr, self.accepts, self.traces, self.tmp = rc, stderr, accepts, traces, tmp
        self.verdicts = {v["id"]: v for v in verdicts}
        self.nb_verdicts = len(verdicts)
        self.remises = [v["id"] for v in verdicts]

    def trace(self, nom):
        return self.traces.get(nom, "")


def jouer(script, central, lecteurs=(), backend="auto", bouchons=("cscli",), env_plus=None, url=None,
          piege_python=False, rejeu_initial=None, faux_binaires=None, etat=None, fond=None):
    """`etat` : répertoire d'état PARTAGÉ entre plusieurs tours (`PLUME_STATE`), au lieu du bac du tour.
    `fond` : une fonction appelée avec le processus lancé EN FOND (Popen), pendant qu'il tourne — pour jouer une
    seconde exécution simultanée ; le script tourne alors dans sa propre session, si bien qu'un bouchon qui tue
    son groupe (`kill -9 0`, arrêt brutal simulé) ne tue jamais l'instrument."""
    with tempfile.TemporaryDirectory() as tmp:
        binaire = os.path.join(tmp, "bin")
        os.makedirs(binaire)
        for outil in OUTILS + list(lecteurs):
            vrai = shutil.which(outil)
            if not vrai:
                refuser_de_conclure(f"`{outil}` introuvable sur cette machine : la garde refuse de conclure")
            os.symlink(vrai, os.path.join(binaire, outil))
        for nom in bouchons:
            with open(os.path.join(binaire, nom), "w") as f:
                f.write(BOUCHON_NFT if nom == "nft" else BOUCHON.replace(".NOM", "." + nom))
            os.chmod(os.path.join(binaire, nom), 0o755)
        for nom, contenu in (faux_binaires or {}).items():
            # Un faux outil (un lecteur JSON qui échoue, par exemple), posé SUR PATH à la place du vrai. Un lien
            # déjà posé vers le vrai outil est RETIRÉ d'abord : écrire à travers lui écraserait le binaire du poste.
            if os.path.lexists(os.path.join(binaire, nom)):
                os.remove(os.path.join(binaire, nom))
            with open(os.path.join(binaire, nom), "w") as f:
                f.write(contenu)
            os.chmod(os.path.join(binaire, nom), 0o755)
        epargne = os.path.join(tmp, "epargne.allow")
        with open(epargne, "w") as f:
            f.write("203.0.113.99\n")
        trace = os.path.join(tmp, "trace")
        env = {"PATH": binaire, "PLUME_RESPONDER": "1", "PLUME_RESPONDER_APPLY": "1",
               "PLUME_CENTRAL": url or central.url, "PLUME_HOST_LABEL": "hote-de-garde",
               "PLUME_TOKEN": "jeton-de-garde", "PLUME_BAN_BACKEND": backend, "PLUME_BAN_DURATION": "7h",
               "PLUME_RESPONDER_ALLOW": epargne, "PLUME_STATE": etat or tmp, "TRACE_ENFORCEMENT": trace,
               "CANARI": os.path.join(tmp, "canari")}
        env.update(env_plus or {})
        cwd = None
        if piege_python:
            # Un `json.py` piégé dans le répertoire courant ET dans PYTHONPATH : seul `python3 -I` l'ignore.
            cwd = os.path.join(tmp, "piege")
            os.makedirs(cwd)
            with open(os.path.join(cwd, "json.py"), "w") as f:
                f.write("import os\nopen(os.environ['CANARI'], 'w').close()\nraise ImportError('json piege')\n")
            env["PYTHONPATH"] = cwd
        if rejeu_initial:
            # Verdicts déjà retenus pour rejeu (forme de `retenir_pour_rejeu`), posés avant le tour.
            rep = os.path.join(tmp, "responder")
            os.makedirs(rep, mode=0o700)
            with open(os.path.join(rep, "verdicts-a-remettre"), "w") as f:
                f.write("".join(l + "\n" for l in rejeu_initial))
        if fond is not None:
            pr = subprocess.Popen([shutil.which("sh"), script], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace", cwd=cwd, start_new_session=True)
            try:
                fond(pr, env)
                sortie, err = pr.communicate(timeout=DELAI_D_UN_TOUR_S)
                p = subprocess.CompletedProcess([], pr.returncode, sortie, err)
            except subprocess.TimeoutExpired:
                os.killpg(pr.pid, 9)
                pr.communicate()
                p = subprocess.CompletedProcess([], -1, "", f"TOUR SANS FIN : le script n'a pas fini en {DELAI_D_UN_TOUR_S} s")
        else:
            try:
                # Sorties décodées avec remplacement : un script (ou un mutant) qui coupe au milieu d'un caractère écrit un
                # journal invalide ; c'est le verdict remis qui est jugé, l'instrument ne doit pas tomber dessus.
                p = subprocess.run([shutil.which("sh"), script], env=env, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=DELAI_D_UN_TOUR_S, cwd=cwd,
                                   start_new_session=True)
            except subprocess.TimeoutExpired:
                # Un tour qui ne finit pas (boucle sans borne) est une propriété violée, jamais un tour conclu : code
                # -1, stderr qui le dit, aucun verdict compté (ceux déjà remis restent, le scénario les juge).
                p = subprocess.CompletedProcess([], -1, "", f"TOUR SANS FIN : le script n'a pas fini en {DELAI_D_UN_TOUR_S} s")
        traces = {}
        for nom in ("cscli", "nft", "fail2ban-client"):
            chemin = f"{trace}.{nom}"
            traces[nom] = open(chemin).read() if os.path.exists(chemin) else ""
        canari = os.path.exists(env["CANARI"])
        t = Tour(p.returncode, p.stderr, central.verdicts if central else [], central.accepts if central else [],
                 traces, tmp)
        t.canari = canari
        t.corps_remis = list(central.corps_remis) if central else []
        return t


# Un lecteur JSON qui écrit un enregistrement A PUIS sort en échec : sa sortie partielle ne doit jamais servir.
FAUX_LECTEUR_EN_ECHEC = """#!/bin/sh
cat > /dev/null
printf 'A\\t571\\tban_ip\\t203.0.113.57\\t0\\t60\\n'
exit 5
"""


def s_lecteur_en_echec(script, nom):
    """Un lecteur JSON en échec (code non nul) : AUCUNE action exécutée, même la partie qu'il a écrite, et
    sortie 3 nommée — jamais un tour « vide » en sortie 0."""
    c = Central("demon", [ban(571, "203.0.113.57", 60), ban(572, "203.0.113.58", 60)])
    try:
        t = jouer(script, c, faux_binaires={nom: FAUX_LECTEUR_EN_ECHEC})
    finally:
        c.fermer()
    f = []
    exiger(f, t.rc == 3, f"lecteur {nom} en échec : rc={t.rc}, attendu 3 : {t.stderr[-300:]!r}")
    exiger(f, "en ECHEC" in t.stderr, f"l'échec du lecteur {nom} n'est pas dit : {t.stderr[-300:]!r}")
    exiger(f, t.trace("cscli") == "" and t.nb_verdicts == 0,
           f"lecteur {nom} en échec : sa sortie partielle a été exécutée : {t.trace('cscli')!r}")
    return f


def s_mktemp_refuse(script):
    """Un fichier temporaire refusé (TMPDIR inexistant) : la file n'est pas lue, sortie 3 nommée."""
    c = Central("demon", [ban(573, "203.0.113.59", 60)])
    try:
        t = jouer(script, c, lecteurs=("python3",), env_plus={"TMPDIR": "/nonexistent-plume-guard"})
    finally:
        c.fermer()
    f = []
    exiger(f, t.rc == 3, f"mktemp refusé : rc={t.rc}, attendu 3 : {t.stderr[-300:]!r}")
    exiger(f, "fichier temporaire refuse" in t.stderr, f"le refus de mktemp n'est pas dit : {t.stderr[-300:]!r}")
    exiger(f, t.trace("cscli") == "", f"mktemp refusé : une action a été exécutée : {t.trace('cscli')!r}")
    return f


def s_json_non_demande_sans_lecteur(script):
    """Une file JSON servie SANS avoir été demandée, sur un hôte sans lecteur : rien d'exécuté, sortie 3."""
    c = Central("statut", statut=200, type_contenu=TYPE_JSON, corps=json.dumps(ban(574, "203.0.113.60", 60)) + "\n")
    try:
        t = jouer(script, c, lecteurs=())
    finally:
        c.fermer()
    f = []
    exiger(f, t.rc == 3, f"JSON non demandé : rc={t.rc}, attendu 3 : {t.stderr[-300:]!r}")
    exiger(f, "SANS avoir ete demandee" in t.stderr, f"le JSON non demandé n'est pas dit : {t.stderr[-300:]!r}")
    exiger(f, t.trace("cscli") == "" and t.nb_verdicts == 0, "JSON non demandé : une action a été exécutée")
    return f


def s_tsv_sans_fin_de_ligne(script):
    """La dernière ligne TSV sans saut de ligne final est servie comme les autres."""
    c = Central("statut", statut=200, type_contenu="text/plain; charset=utf-8", corps="575\tban_ip\t203.0.113.61\t0")
    try:
        t = jouer(script, c, lecteurs=())
    finally:
        c.fermer()
    f = []
    verdict_est(f, t, 575, "done", "-d 7h")
    return f


def s_grand_id(script, lecteur):
    """Un id au-delà de 2^53-1 est illisible pour les deux lecteurs : jamais arrondi vers l'id d'un autre."""
    c = Central("demon", lignes_json=['{"id":9007199254740993,"kind":"ban_ip","target":"203.0.113.62","dry_run":false,"ban_ttl_s":60}'])
    try:
        t = jouer(script, c, lecteurs=(lecteur,))
    finally:
        c.fermer()
    f = []
    exiger(f, "ligne 1 ILLISIBLE (cause=id_illisible)" in t.stderr, f"{lecteur} : grand id non refusé : {t.stderr[-300:]!r}")
    exiger(f, t.nb_verdicts == 0 and t.trace("cscli") == "",
           f"{lecteur} : grand id appliqué ou remis : {sorted(t.verdicts)!r} {t.trace('cscli')!r}")
    return f


def s_id_moins_zero(script, lecteur):
    """Un id -0 est l'id 0 pour les deux lecteurs : jamais une ligne perdue sans verdict ni journal."""
    c = Central("demon", lignes_json=['{"id":-0,"kind":"ban_ip","target":"203.0.113.63","dry_run":false,"ban_ttl_s":60}'])
    try:
        t = jouer(script, c, lecteurs=(lecteur,))
    finally:
        c.fermer()
    f = []
    verdict_est(f, t, 0, "done", "-d 60s")
    return f


def s_nft_repli_sans_ancre(script):
    """Une durée de repli qui COMMENCE comme une durée nft est refusée entière, jamais posée : `4hours` (lettres
    hors de [0-9dhms]) comme `4hd` (seulement [0-9dhms], mais mal formée : c'est l'ancrage de l'ERE qui la refuse)."""
    f = []
    for i, valeur in ((576, "4hours"), (583, "4hd")):
        c = Central("tsv", [ban(i, f"203.0.113.{i - 500}")])
        try:
            t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",), env_plus={"PLUME_BAN_DURATION": valeur})
        finally:
            c.fermer()
        exiger(f, not POSE_NFT.search(t.trace("nft")), f"`{valeur}` posé en nft : {t.trace('nft')!r}")
        verdict_est(f, t, i, "failed", "illisible")
    return f


def s_repli_multiligne(script):
    """Un PLUME_BAN_DURATION MULTILIGNE (`4h`, `}`, `add table ...`) est refusé ENTIER : rien ne part à nft, et
    surtout pas ses lignes en trop comme commandes."""
    c = Central("tsv", [ban(577, "203.0.113.65")])
    try:
        t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",),
                  env_plus={"PLUME_BAN_DURATION": "4h\n}\nadd table inet pwned"})
    finally:
        c.fermer()
    f = []
    exiger(f, "pwned" not in t.trace("nft") and not POSE_NFT.search(t.trace("nft")),
           f"une durée de repli multiligne part à nft : {t.trace('nft')!r}")
    verdict_est(f, t, 577, "failed", "illisible")
    return f


def s_crowdsec_repli_invalide(script):
    """Sur crowdsec, une durée de repli illisible ou nulle n'est jamais passée à cscli : `failed` avec la cause ;
    en simulation, NON-APPLIQUE."""
    f = []
    for i, valeur in ((578, "0s"), (579, "-1h"), (580, "abc"), (581, "4h\n-t captcha"), (584, "4hd")):
        c = Central("tsv", [ban(i, f"203.0.113.{i - 500}")])
        try:
            t = jouer(script, c, lecteurs=(), env_plus={"PLUME_BAN_DURATION": valeur})
        finally:
            c.fermer()
        exiger(f, t.trace("cscli") == "", f"PLUME_BAN_DURATION={valeur!r} passé à cscli : {t.trace('cscli')!r}")
        verdict_est(f, t, i, "failed", "illisible ou nulle pour cscli")
        execution_dit(f, t, i, "(cause : nulle)" if valeur == "0s" else "(cause : illisible")
    for i, valeur, cause in ((582, "abc", "(cause : illisible"), (583, "0s", "(cause : nulle)")):
        c = Central("tsv", [ban(i, f"203.0.113.{i - 500}")])
        try:
            t = jouer(script, c, lecteurs=(), env_plus={"PLUME_BAN_DURATION": valeur, "PLUME_RESPONDER_APPLY": "0"})
        finally:
            c.fermer()
        verdict_est(f, t, i, "dryrun", "NON-APPLIQUE crowdsec", cause)
    return f

# ----------------------------------------------------------------------------------------------------------
# SCÉNARIOS — chacun rend la liste de ses fautes (vide = vert).
# ----------------------------------------------------------------------------------------------------------
def exiger(fautes, cond, msg):
    if not cond:
        fautes.append(msg)


def verdict_est(fautes, t, i, statut, *contient):
    v = t.verdicts.get(i)
    if v is None:
        fautes.append(f"#{i} : aucun verdict remis (stderr={t.stderr[-400:]!r})")
        return
    exiger(fautes, v["status"] == statut, f"#{i} : statut {v['status']!r}, attendu {statut!r} ({v['result'][:300]!r})")
    for c in contient:
        exiger(fautes, c in v["result"], f"#{i} : le résultat remis ne dit pas {c!r} ({v['result'][:300]!r})")


def execution_dit(fautes, t, i, *contient):
    """Ce que dit l'EXÉCUTION elle-même (la partie après « | » du verdict appliqué), pas le plan qui la précède :
    le plan porte souvent la même cause, et un témoin qui lit tout le verdict ne verrait pas l'exécution la taire."""
    v = t.verdicts.get(i)
    if v is None:
        return
    apres = v["result"].split(" | ", 1)[1] if " | " in v["result"] else ""
    for c in contient:
        exiger(fautes, c in apres, f"#{i} : l'exécution ne dit pas {c!r} (après la barre : {apres[:300]!r})")


def s_json_servi(script, lecteur):
    c = Central("demon", [ban(101, "203.0.113.41", 5400, inconnu="ignore-moi"), unban(102, "203.0.113.42")])
    try:
        t = jouer(script, c, lecteurs=(lecteur,))
    finally:
        c.fermer()
    f = []
    exiger(f, any(a and TYPE_JSON in a for a in t.accepts), f"l'en-tête Accept {TYPE_JSON} n'est pas envoyé ({t.accepts!r})")
    exiger(f, "decisions add -i 203.0.113.41 -d 5400s -t ban" in t.trace("cscli"),
           f"cscli ne reçoit pas la durée servie : {t.trace('cscli')!r}")
    verdict_est(f, t, 101, "done", "-d 5400s", "servie par le central")
    verdict_est(f, t, 102, "done")
    exiger(f, "decisions delete -i 203.0.113.42" in t.trace("cscli"), f"l'unban n'est pas appliqué : {t.trace('cscli')!r}")
    exiger(f, t.rc == 0, f"rc={t.rc} : {t.stderr[-300:]!r}")
    return f


def s_sans_lecteur_repli_dit(script):
    c = Central("demon", [ban(111, "203.0.113.43", 5400)])
    try:
        t = jouer(script, c, lecteurs=())
    finally:
        c.fermer()
    f = []
    exiger(f, not any(a and TYPE_JSON in a for a in t.accepts), f"Accept JSON envoyé SANS lecteur : {t.accepts!r}")
    exiger(f, "decisions add -i 203.0.113.43 -d 7h -t ban" in t.trace("cscli"), f"repli absent : {t.trace('cscli')!r}")
    verdict_est(f, t, 111, "done", "PLUME_BAN_DURATION", "aucun lecteur JSON")
    return f


def s_central_anterieur_tsv(script):
    c = Central("tsv", [ban(121, "203.0.113.44", 5400)])
    try:
        t = jouer(script, c, lecteurs=("python3",))
    finally:
        c.fermer()
    f = []
    exiger(f, any(a and TYPE_JSON in a for a in t.accepts), f"Accept JSON non envoyé alors que python3 est là : {t.accepts!r}")
    exiger(f, "decisions add -i 203.0.113.44 -d 7h -t ban" in t.trace("cscli"), f"TSV servi : repli absent : {t.trace('cscli')!r}")
    verdict_est(f, t, 121, "done", "PLUME_BAN_DURATION", "TSV malgre")
    return f


def s_type_casse_libre(script):
    c = Central("demon", [ban(131, "203.0.113.45", 600)], type_contenu="Application/X-NDJSON; charset=utf-8")
    try:
        t = jouer(script, c, lecteurs=("python3",))
    finally:
        c.fermer()
    f = []
    verdict_est(f, t, 131, "done", "-d 600s", "servie par le central")
    return f


def s_statut_non_200(script, lecteurs, type_contenu, corps):
    c = Central("statut", statut=503, type_contenu=type_contenu, corps=corps)
    try:
        t = jouer(script, c, lecteurs=lecteurs)
    finally:
        c.fermer()
    f = []
    exiger(f, t.rc == 3, f"rc={t.rc}, attendu 3 (sortie classée) : {t.stderr[-300:]!r}")
    exiger(f, "HTTP 503" in t.stderr and "NON LUE" in t.stderr, f"le 503 n'est pas nommé sur stderr : {t.stderr[-300:]!r}")
    exiger(f, t.trace("cscli") == "", f"le corps d'un 503 a été EXÉCUTÉ : {t.trace('cscli')!r}")
    exiger(f, t.nb_verdicts == 0, f"des verdicts ont été remis sur un 503 : {t.verdicts!r}")
    return f


def s_central_injoignable(script):
    c = Central("demon", [])
    url = c.url
    c.fermer()   # port fermé : curl échoue
    t = jouer(script, None, lecteurs=("python3",), url=url)
    f = []
    exiger(f, t.rc == 3, f"rc={t.rc}, attendu 3 : {t.stderr[-300:]!r}")
    exiger(f, "NON LUE" in t.stderr, f"l'échec de curl n'est pas nommé : {t.stderr[-300:]!r}")
    return f


def s_ligne_illisible(script, lecteur):
    lignes = [json.dumps(ban(301, "203.0.113.61", 600)), '{"id":302,"kind":"ban_ip",', "pas du json",
              "[1,2]", json.dumps(unban(305, "203.0.113.65"))]
    c = Central("demon", lignes_json=lignes)
    try:
        t = jouer(script, c, lecteurs=(lecteur,))
    finally:
        c.fermer()
    f = []
    verdict_est(f, t, 301, "done", "-d 600s")
    verdict_est(f, t, 305, "done")
    for n in (2, 3, 4):
        exiger(f, f"ligne {n} ILLISIBLE" in t.stderr, f"la ligne {n} illisible n'est pas dite : {t.stderr[-500:]!r}")
    exiger(f, 302 not in t.verdicts, "une ligne illisible a produit un verdict")
    exiger(f, t.rc == 0, f"rc={t.rc}")
    return f


HORS_CONTRAT = [  # (id, valeur ou ABSENT, cause attendue)
    (401, "5400", "non_numerique"), (402, 5400.5, "non_entiere"), (403, 0, "hors_borne"),
    (404, None, "nulle"), (405, "ABSENT", "absente"), (406, True, "non_numerique"), (407, -5, "hors_borne"),
]


def s_duree_hors_contrat(script, lecteur):
    lignes = []
    for i, v, _ in HORS_CONTRAT:
        a = {"id": i, "kind": "ban_ip", "target": f"198.51.100.{i - 390}", "dry_run": False}
        if v != "ABSENT":
            a["ban_ttl_s"] = v
        lignes.append(json.dumps(a))
    lignes.append(f'{{"id":408,"kind":"ban_ip","target":"198.51.100.18","dry_run":false,"ban_ttl_s":{BORNE + 1}}}')
    lignes.append(f'{{"id":409,"kind":"ban_ip","target":"198.51.100.19","dry_run":false,"ban_ttl_s":{BORNE}}}')
    lignes.append('{"id":410,"kind":"ban_ip","target":"198.51.100.20","dry_run":false,"ban_ttl_s":5400.0}')
    lignes.append('{"id":411,"kind":"ban_ip","target":"198.51.100.21","dry_run":false,"ban_ttl_s":1}')
    c = Central("demon", lignes_json=lignes)
    try:
        t = jouer(script, c, lecteurs=(lecteur,))
    finally:
        c.fermer()
    f = []
    for i, _, cause in HORS_CONTRAT + [(408, None, "hors_borne")]:
        verdict_est(f, t, i, "failed", "HORS CONTRAT", f"cause={cause}")
        exiger(f, f"198.51.100.{i - 390} " not in t.trace("cscli"), f"#{i} hors contrat APPLIQUÉ : {t.trace('cscli')!r}")
    verdict_est(f, t, 409, "done", f"-d {BORNE}s")
    verdict_est(f, t, 410, "done", "-d 5400s")
    verdict_est(f, t, 411, "done", "-d 1s")
    return f


def s_nft_set_a_duree(script):
    c = Central("demon", [ban(501, "203.0.113.71", 5400)])
    try:
        t = jouer(script, c, lecteurs=("python3",), backend="nft", bouchons=("nft",))
    finally:
        c.fermer()
    f = []
    n = t.trace("nft")
    exiger(f, "add set inet plume blocklist_ttl { type ipv4_addr; flags timeout; }" in n, f"set à durée non créé : {n!r}")
    exiger(f, "add rule inet plume input ip saddr @blocklist_ttl drop" in n, f"règle du set à durée absente : {n!r}")
    # `P11.25-a` : la pose est EXCLUSIVE (`create element`) — `add element` remplaçait le délai d'une adresse déjà
    # bannie, donc pouvait le raccourcir. Ce témoin exigeait `add element` : il exige désormais `create element`.
    exiger(f, "create element inet plume blocklist_ttl { 203.0.113.71 timeout 5400s }" in n, f"élément sans timeout servi : {n!r}")
    exiger(f, not re.search(r"(add|create) element inet plume blocklist \{", n), f"ban PERMANENT posé dans l'ancien set : {n!r}")
    exiger(f, not re.search(r"(delete|flush) (set|table)", n), f"l'ancien set/table est détruit : {n!r}")
    verdict_est(f, t, 501, "done", "timeout 5400s", "servie par le central")
    return f


def s_nft_repli_illisible(script):
    c = Central("tsv", [ban(511, "203.0.113.72")])
    try:
        t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",), env_plus={"PLUME_BAN_DURATION": "4 heures"})
    finally:
        c.fermer()
    f = []
    exiger(f, not POSE_NFT.search(t.trace("nft")), f"un ban nft est posé avec une durée illisible : {t.trace('nft')!r}")
    verdict_est(f, t, 511, "failed", "illisible")
    return f


def s_fail2ban_duree_non_portee(script):
    c = Central("demon", [ban(601, "203.0.113.81", 5400)])
    try:
        t = jouer(script, c, lecteurs=("python3",), backend="fail2ban", bouchons=("fail2ban-client",))
    finally:
        c.fermer()
    f = []
    exiger(f, "set sshd banip 203.0.113.81" in t.trace("fail2ban-client"), f"fail2ban non appelé : {t.trace('fail2ban-client')!r}")
    verdict_est(f, t, 601, "done", "5400s", "NON portee par fail2ban", "bantime")
    return f


def s_simulation(script):
    c = Central("demon", [ban(701, "203.0.113.91", 5400)])
    try:
        t = jouer(script, c, lecteurs=("python3",), env_plus={"PLUME_RESPONDER_APPLY": "0"})
    finally:
        c.fermer()
    c2 = Central("tsv", [ban(702, "203.0.113.92")])
    try:
        t2 = jouer(script, c2, lecteurs=(), env_plus={"PLUME_RESPONDER_APPLY": "0"})
    finally:
        c2.fermer()
    f = []
    verdict_est(f, t, 701, "dryrun", "-d 5400s", "servie par le central")
    verdict_est(f, t2, 702, "dryrun", "-d 7h", "PLUME_BAN_DURATION", "aucun lecteur JSON")
    exiger(f, "decisions add" not in t.trace("cscli") + t2.trace("cscli"), "une simulation a appliqué un ban")
    return f


def s_valeurs_servies_jamais_evaluees(script, lecteur):
    lignes = [
        '{"id":801,"kind":"ban_ip","target":"$(touch $CANARI)","dry_run":false,"ban_ttl_s":60}',
        '{"id":802,"kind":"ban_ip","target":"203.0.113.9;touch${IFS}$CANARI","dry_run":false,"ban_ttl_s":60}',
        '{"id":803,"kind":"ban\\tip","target":"203.0.113.10","dry_run":false,"ban_ttl_s":60}',
        '{"id":804,"kind":"ban_ip","target":"203.0.113.11","dry_run":false,"ban_ttl_s":"60;touch $CANARI"}',
        '{"id":805,"kind":"ban_ip","target":"10.0.0.5","dry_run":false,"ban_ttl_s":60}',
        '{"id":806,"kind":"ban_ip","target":"203.0.113.99","dry_run":false,"ban_ttl_s":60}',
        '{"id":807,"kind":"ban_ip","target":"203.0.113.12","dry_run":"0","ban_ttl_s":60}',
        '{"id":808,"kind":"ban_ip","target":"203.0.113.13","dry_run":null,"ban_ttl_s":60}',
        '{"id":809,"kind":"ban_ip","target":"203.0.113.14","ban_ttl_s":60}',
        # lignes 10 à 13 : `id` illisible => ligne IGNORÉE ET DITE, jamais appliquée sous un autre numéro.
        '{"id":1.5,"kind":"ban_ip","target":"203.0.113.15","dry_run":false,"ban_ttl_s":60}',
        '{"id":"abc","kind":"ban_ip","target":"203.0.113.16","dry_run":false,"ban_ttl_s":60}',
        '{"id":-1,"kind":"ban_ip","target":"203.0.113.17","dry_run":false,"ban_ttl_s":60}',
        '{"kind":"ban_ip","target":"203.0.113.18","dry_run":false,"ban_ttl_s":60}',
        # ... et la file continue : l'unban qui suit est appliqué.
        json.dumps(unban(814, "203.0.113.19")),
    ]
    c = Central("demon", lignes_json=lignes)
    try:
        t = jouer(script, c, lecteurs=(lecteur,))
    finally:
        c.fermer()
    f = []
    exiger(f, not t.canari, "une valeur servie a été ÉVALUÉE par le shell (canari créé)")
    exiger(f, "decisions add" not in t.trace("cscli"), f"une action hors contrat a atteint cscli : {t.trace('cscli')!r}")
    exiger(f, "decisions delete -i 203.0.113.19" in t.trace("cscli"), f"la file s'est arrêtée avant l'unban : {t.trace('cscli')!r} (stderr={t.stderr[-300:]!r})")
    exiger(f, t.rc == 0, f"rc={t.rc} : {t.stderr[-300:]!r}")
    for n in (10, 11, 12, 13):
        exiger(f, f"ligne {n} ILLISIBLE (cause=id_illisible)" in t.stderr, f"la ligne {n} (id illisible) n'est pas dite : {t.stderr[-500:]!r}")
    exiger(f, not (set(t.verdicts) & {0, 1}), f"un id illisible a été lu comme un autre numéro : {sorted(t.verdicts)!r}")
    verdict_est(f, t, 814, "done")
    verdict_est(f, t, 801, "failed", "target_illisible")
    verdict_est(f, t, 802, "failed", "cible non-IP")
    verdict_est(f, t, 803, "failed", "kind_illisible")
    verdict_est(f, t, 804, "failed", "cause=non_numerique")
    verdict_est(f, t, 805, "failed", "IP protegee")
    verdict_est(f, t, 806, "failed", "liste d epargne")
    verdict_est(f, t, 807, "failed", "dry_run_illisible")
    verdict_est(f, t, 808, "failed", "dry_run_illisible")
    verdict_est(f, t, 809, "failed", "dry_run_illisible")
    return f


def s_nft_unban_set_a_duree(script):
    c = Central("demon", [unban(521, "203.0.113.31")])
    try:
        t = jouer(script, c, lecteurs=("python3",), backend="nft", bouchons=("nft",), env_plus={"NFT_ETAT": "equipe"})
    finally:
        c.fermer()
    f = []
    n = t.trace("nft")
    exiger(f, "delete element inet plume blocklist_ttl { 203.0.113.31 }" in n,
           f"l'unban laisse le ban à durée en place (jusqu'à la borne) : {n!r}")
    exiger(f, "delete element inet plume blocklist { 203.0.113.31 }" in n, f"l'unban oublie l'ancien set : {n!r}")
    verdict_est(f, t, 521, "done", "[nft-ttl]")
    return f


def s_nft_hote_neuf(script):
    c = Central("demon", [ban(531, "203.0.113.32", 600)])
    try:
        t = jouer(script, c, lecteurs=("python3",), backend="nft", bouchons=("nft",), env_plus={"NFT_ETAT": "neuf"})
    finally:
        c.fermer()
    f = []
    n = t.trace("nft")
    for attendu in ("add table inet plume", "add set inet plume blocklist { type ipv4_addr; flags interval; }",
                    "add chain inet plume input { type filter hook input priority -150; policy accept; }",
                    "add rule inet plume input ip saddr @blocklist drop",
                    "add set inet plume blocklist_ttl { type ipv4_addr; flags timeout; }",
                    "add rule inet plume input ip saddr @blocklist_ttl drop",
                    "create element inet plume blocklist_ttl { 203.0.113.32 timeout 600s }"):
        exiger(f, attendu in n, f"hôte neuf : `{attendu}` absent : {n!r}")
    verdict_est(f, t, 531, "done", "timeout 600s")
    return f


def s_nft_repli_nul(script):
    f = []
    for i, valeur in ((541, "0s"), (542, "00h0m")):
        c = Central("tsv", [ban(i, f"203.0.113.{i - 500}")])
        try:
            t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",), env_plus={"PLUME_BAN_DURATION": valeur})
        finally:
            c.fermer()
        exiger(f, not POSE_NFT.search(t.trace("nft")), f"PLUME_BAN_DURATION={valeur} : élément nft posé (timeout nul) : {t.trace('nft')!r}")
        # « nulle » seul se lit déjà dans « illisible ou nulle » : c'est la CAUSE qui est exigée, au plan et à l'exécution.
        verdict_est(f, t, i, "failed", "(cause : nulle)")
        execution_dit(f, t, i, "(cause : nulle)")
    for i, valeur, cause in ((543, "0s", "(cause : nulle)"), (544, "4hd", "(cause : illisible")):
        c = Central("tsv", [ban(i, f"203.0.113.{i - 500}")])
        try:
            t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",),
                      env_plus={"PLUME_BAN_DURATION": valeur, "PLUME_RESPONDER_APPLY": "0"})
        finally:
            c.fermer()
        verdict_est(f, t, i, "dryrun", "[dry-run] NON-APPLIQUE nft", cause)
    return f


def s_200_tronque(script, lecteur):
    """Statut 200, mais le corps annoncé n'arrive pas en entier : curl échoue (code 18). La partie reçue
    n'est PAS une file : la dernière ligne y est coupée au milieu d'une adresse."""
    if lecteur:
        corps = json.dumps(ban(571, "203.0.113.57", 60)) + "\n" + '{"id":572,"kind":"ban_ip","target":"203.0.113.1'
        c = Central("statut", statut=200, type_contenu=TYPE_JSON, corps=corps, longueur_annoncee=len(corps) + 200)
    else:
        corps = "571\tban_ip\t203.0.113.57\t0\n572\tban_ip\t203.0.113.1"
        c = Central("statut", statut=200, type_contenu="text/plain", corps=corps, longueur_annoncee=len(corps) + 200)
    try:
        t = jouer(script, c, lecteurs=(lecteur,) if lecteur else ())
    finally:
        c.fermer()
    f = []
    exiger(f, t.rc == 3, f"rc={t.rc}, attendu 3 : {t.stderr[-300:]!r}")
    exiger(f, "NON LUE" in t.stderr and "curl code 18" in t.stderr, f"l'échec de curl sous un 200 n'est pas nommé : {t.stderr[-300:]!r}")
    exiger(f, t.trace("cscli") == "", f"un corps TRONQUÉ a été exécuté : {t.trace('cscli')!r}")
    exiger(f, t.nb_verdicts == 0, f"des verdicts ont été remis sur un corps tronqué : {t.verdicts!r}")
    return f


def s_200_trop_gros(script):
    borne = int(re.search(r"^FILE_OCTETS_MAX=(\d+)$", open(script, encoding="utf-8").read(), re.M).group(1))
    corps = "581\tban_ip\t203.0.113.58\t0\n" + "#" * (borne + 4096) + "\n"
    c = Central("statut", statut=200, type_contenu="text/plain", corps=corps)
    try:
        t = jouer(script, c, lecteurs=())
    finally:
        c.fermer()
    f = []
    exiger(f, t.rc == 3, f"rc={t.rc}, attendu 3 (corps au-delà de {borne} octets) : {t.stderr[-300:]!r}")
    exiger(f, t.trace("cscli") == "", f"un corps au-delà de la borne a été exécuté : {t.trace('cscli')!r}")
    exiger(f, t.nb_verdicts == 0, f"des verdicts ont été remis sur un corps hors borne : {t.verdicts!r}")
    return f


def s_python_isole(script):
    c = Central("demon", [ban(551, "203.0.113.55", 600)])
    try:
        t = jouer(script, c, lecteurs=("python3",), piege_python=True)
    finally:
        c.fermer()
    f = []
    exiger(f, not t.canari, "le lecteur python3 a chargé un json.py du répertoire courant / de PYTHONPATH (canari créé)")
    verdict_est(f, t, 551, "done", "-d 600s")
    return f


def s_f_en_attente(script):
    """Une action hors contrat (ligne F) dont le verdict attend DÉJÀ sa remise ne reçoit pas un second
    verdict : le central refuse la remise (503), seul le rejeu la tente, une fois."""
    ligne = json.dumps({"id": 561, "kind": "ban\tip", "target": "203.0.113.56", "dry_run": False, "ban_ttl_s": 60})
    c = Central("demon", lignes_json=[ligne], statut_remise=503)
    try:
        t = jouer(script, c, lecteurs=("python3",),
                  rejeu_initial=['561\t0\t{"id":561,"status":"done","result":"deja applique"}'])
    finally:
        c.fermer()
    f = []
    exiger(f, t.remises.count(561) == 1, f"#561 remis {t.remises.count(561)} fois, attendu 1 (le rejeu seul) : {t.remises!r}")
    exiger(f, "#561 NON reexecutee" in t.stderr, f"la non-réexécution n'est pas dite : {t.stderr[-400:]!r}")
    return f


# ----------------------------------------------------------------------------------------------------------
# `P11.25-a` — UN BAN PLUS COURT NE RACCOURCIT JAMAIS UN BAN EN COURS (voie nft). Phrases fixes du résultat remis,
# écrites ICI en littéral (jamais relues du script) : un script qui les change fait rougir ces témoins.
# ----------------------------------------------------------------------------------------------------------
PHRASE_POSE = "BAN POSE"
PHRASE_ALLONGE = "BAN ALLONGE"
PHRASE_CONSERVE = "DEJA BANNI POUR PLUS LONGTEMPS, DUREE CONSERVEE"
PHRASE_CONSERVE_SANS_FIN = "DEJA BANNI SANS FIN, DUREE CONSERVEE"
PHRASE_NON_APPLIQUEE = "DUREE NON APPLIQUEE, ban en cours conserve tel quel"
PHRASE_TX_REFUSEE = "DUREE NON APPLIQUEE : allongement refuse par nft, transaction annulee entiere"
CAUSE_DESORDRE = "unite repetee ou desordonnee"


def jouer_nft(script, actions, presents=(), env_plus=None, **plus):
    """Un tour nft sur un hôte DÉJÀ équipé (table et set à durée là), file JSON servie (lecteur python3)."""
    env = {"NFT_ETAT": "equipe", "NFT_PRESENTS": " ".join(f"{ip}={m}" for ip, m in presents)}
    env.update(env_plus or {})
    c = Central("demon", actions)
    try:
        return jouer(script, c, lecteurs=("python3",), backend="nft", bouchons=("nft",), env_plus=env, **plus)
    finally:
        c.fermer()


def lignes_nft(t):
    return [l for l in t.trace("nft").splitlines() if l]


def s_nft_ban_court_conserve_le_long(script):
    """Long puis court : l'adresse a 9m59s990ms de reste, le central demande 10 s. Pose exclusive refusée, reste
    lu, AUCUNE commande qui récrit (ni transaction, ni retrait, ni `add`), verdict `done` qui DIT la conservation."""
    t = jouer_nft(script, [ban(901, "203.0.113.21", 10)], presents=[("203.0.113.21", "reste:9m59s990ms")])
    f = []
    attendu = ["list table inet plume", "list set inet plume blocklist_ttl",
               "create element inet plume blocklist_ttl { 203.0.113.21 timeout 10s }",
               "get element inet plume blocklist_ttl { 203.0.113.21 }"]
    exiger(f, lignes_nft(t) == attendu, f"long puis court : commandes nft {lignes_nft(t)!r}, attendu {attendu!r}")
    verdict_est(f, t, 901, "done", PHRASE_CONSERVE, "reste 9m59s990ms >= 10s")
    return f


def s_nft_ban_long_allonge_en_une_transaction(script):
    """Court puis long : reste 9s998ms, 600 s demandées. Retrait PUIS pose dans UNE transaction `nft -f -`, rien
    d'autre ne récrit ; verdict `done` qui dit l'allongement."""
    t = jouer_nft(script, [ban(902, "203.0.113.22", 600)], presents=[("203.0.113.22", "reste:9s998ms")])
    f = []
    attendu = ["list table inet plume", "list set inet plume blocklist_ttl",
               "create element inet plume blocklist_ttl { 203.0.113.22 timeout 600s }",
               "get element inet plume blocklist_ttl { 203.0.113.22 }", "-f -",
               "TX| delete element inet plume blocklist_ttl { 203.0.113.22 }",
               "TX| add element inet plume blocklist_ttl { 203.0.113.22 timeout 600s }"]
    exiger(f, lignes_nft(t) == attendu, f"court puis long : commandes nft {lignes_nft(t)!r}, attendu {attendu!r}")
    verdict_est(f, t, 902, "done", PHRASE_ALLONGE, "reste 9s998ms < 600s")
    return f


def s_nft_absente_pose_simple(script):
    """Adresse absente du set à durée — qu'elle figure ou non dans le set PERMANENT `blocklist`, que le script ne lit
    ni ne touche (comportement d'avant) : les commandes d'avant, la pose étant exclusive ; ni lecture, ni
    transaction ; verdict `done` qui dit la pose."""
    t = jouer_nft(script, [ban(903, "203.0.113.23", 600)])
    f = []
    attendu = ["list table inet plume", "list set inet plume blocklist_ttl",
               "create element inet plume blocklist_ttl { 203.0.113.23 timeout 600s }"]
    exiger(f, lignes_nft(t) == attendu, f"adresse absente : commandes nft {lignes_nft(t)!r}, attendu {attendu!r}")
    verdict_est(f, t, 903, "done", PHRASE_POSE, "timeout 600s")
    exiger(f, t.verdicts.get(903, {}).get("result", "").startswith("nft create element inet plume blocklist_ttl { 203.0.113.23 timeout 600s }"),
           f"le plan remis ne nomme pas la pose exclusive : {t.verdicts.get(903, {}).get('result', '')[:200]!r}")
    return f


RESTES_ILLISIBLES = [  # (id, ip, mode, cause écrite dans le verdict)
    (911, "203.0.113.31", "timeout_sans_expires", "expires_absent"),
    (912, "203.0.113.32", "sortie_inconnue", "adresse_absente_de_la_sortie"),
    (913, "203.0.113.33", "en_double", "adresse_en_double"),
    (914, "203.0.113.34", "reste:9x", "expires_de_forme_inconnue"),
    (915, "203.0.113.35", "reste:59s1d", "expires_de_forme_inconnue"),
    (916, "203.0.113.36", "reste:5m5m", "expires_de_forme_inconnue"),
    (917, "203.0.113.37", "lecture_refusee", "lecture_refusee"),
    (918, "203.0.113.38", "absent_a_chaque_lecture", "element_disparu_apres_la_reprise"),
]


def s_nft_reste_illisible_rien_recrit(script):
    """Reste illisible, chaque cause : l'adresse reste bannie TELLE QUELLE (aucune transaction, aucun retrait,
    aucun `add`), verdict `failed` avec la phrase DUREE NON APPLIQUEE et sa cause — jamais un `done`."""
    t = jouer_nft(script, [ban(i, ip, 10) for i, ip, _, _ in RESTES_ILLISIBLES],
                  presents=[(ip, m) for _, ip, m, _ in RESTES_ILLISIBLES])
    f = []
    recrit = [l for l in lignes_nft(t) if l == "-f -" or l.startswith(("TX|", "add element", "delete element"))]
    exiger(f, recrit == [], f"reste illisible : une commande RÉCRIT le ban : {recrit!r}")
    for i, ip, _, cause in RESTES_ILLISIBLES:
        verdict_est(f, t, i, "failed", PHRASE_NON_APPLIQUEE, "n a pas pu etre lu", f"cause={cause})")
    creates_918 = [l for l in lignes_nft(t) if l.startswith("create element") and "203.0.113.38 " in l]
    exiger(f, len(creates_918) == 2, f"course répétée : {len(creates_918)} poses exclusives, attendu 2 (une reprise, une seule)")
    exiger(f, "syntax error" in t.verdicts.get(917, {}).get("result", ""), "la lecture refusée ne cite pas l'erreur de nft")
    return f


def s_nft_sans_awk_rien_recrit(script):
    """Hôte sans `awk` : le reste n'est pas jugé ; rien n'est récrit, `failed`, cause `lecteur_en_echec`."""
    global OUTILS
    sauve = OUTILS
    OUTILS = [o for o in OUTILS if o != "awk"]
    try:
        t = jouer_nft(script, [ban(919, "203.0.113.39", 10)], presents=[("203.0.113.39", "reste:9m59s990ms")])
    finally:
        OUTILS = sauve
    f = []
    exiger(f, not [l for l in lignes_nft(t) if l == "-f -" or l.startswith(("add element", "delete element"))],
           f"sans awk : une commande récrit le ban : {lignes_nft(t)!r}")
    verdict_est(f, t, 919, "failed", PHRASE_NON_APPLIQUEE, "cause=lecteur_en_echec)")
    return f


FORMES_D_EXPIRES = [  # (id, ip, reste, durée servie en s, issue) — chaque unité, chaque bord
    (921, "198.51.100.21", "1d1h59m59s971ms", 93600, "allonger"),
    (922, "198.51.100.22", "1d1h59m59s971ms", 93599, "conserver"),
    (923, "198.51.100.23", "364d23h59m59s995ms", 31536000, "allonger"),
    (924, "198.51.100.24", "364d23h59m59s995ms", 31535999, "conserver"),
    (925, "198.51.100.25", "23h59m59s998ms", 86400, "allonger"),
    (926, "198.51.100.26", "23h59m59s998ms", 86399, "conserver"),
    (927, "198.51.100.27", "58m59s997ms", 3540, "allonger"),
    (928, "198.51.100.28", "58m59s997ms", 3539, "conserver"),
    (929, "198.51.100.29", "1s996ms", 2, "allonger"),
    (930, "198.51.100.30", "1s996ms", 1, "conserver"),
    (931, "198.51.100.31", "490ms", 1, "allonger"),
    (932, "198.51.100.32", "10s", 10, "conserver"),
    (933, "198.51.100.33", "10s", 11, "allonger"),
    (934, "198.51.100.34", "2h", 7200, "conserver"),
    (935, "198.51.100.35", "1m30s", 91, "allonger"),
]


def s_nft_chaque_forme_d_expires(script):
    """Chaque forme d'`expires` (jours à millisecondes, unité seule, reste ÉGAL à la demande) jugée au bord."""
    t = jouer_nft(script, [ban(i, ip, d) for i, ip, _, d, _ in FORMES_D_EXPIRES],
                  presents=[(ip, f"reste:{r}") for _, ip, r, _, _ in FORMES_D_EXPIRES])
    f = []
    for i, ip, r, d, issue in FORMES_D_EXPIRES:
        tx = f"TX| add element inet plume blocklist_ttl {{ {ip} timeout {d}s }}"
        if issue == "allonger":
            verdict_est(f, t, i, "done", PHRASE_ALLONGE, f"reste {r} < {d}s")
            exiger(f, tx in lignes_nft(t), f"#{i} ({r} contre {d}s) : pas de transaction d'allongement")
        else:
            verdict_est(f, t, i, "done", PHRASE_CONSERVE, f"reste {r} >= {d}s")
            exiger(f, tx not in lignes_nft(t), f"#{i} ({r} contre {d}s) : ban RACCOURCI ou récrit")
    return f


def s_nft_expire_avant_la_lecture(script):
    """L'élément expire entre la pose exclusive refusée et la lecture : UNE nouvelle pose exclusive, qui réussit.
    DEUX bans du MÊME tour croisent chacun cette course : la reprise appartient à CHAQUE ban, un compteur partagé
    par le tour laisserait le second `failed` et son adresse non bannie."""
    t = jouer_nft(script, [ban(941, "203.0.113.41", 600), ban(945, "203.0.113.45", 600)],
                  presents=[("203.0.113.41", "expire_a_la_lecture"), ("203.0.113.45", "expire_a_la_lecture")])
    f = []
    for i, ip in ((941, "203.0.113.41"), (945, "203.0.113.45")):
        creates = [l for l in lignes_nft(t) if l.startswith("create element") and f" {ip} " in l]
        exiger(f, len(creates) == 2, f"course avant la lecture ({ip}) : {len(creates)} poses exclusives, attendu 2")
        verdict_est(f, t, i, "done", PHRASE_POSE)
    exiger(f, "-f -" not in lignes_nft(t), "course avant la lecture : une transaction est partie")
    return f


def s_nft_expire_avant_la_transaction(script):
    """L'élément expire entre la lecture et la transaction (annulée entière) : UNE nouvelle pose exclusive."""
    t = jouer_nft(script, [ban(942, "203.0.113.42", 600)], presents=[("203.0.113.42", "reste:1s")],
                  env_plus={"NFT_TX": "expiree:203.0.113.42"})
    f = []
    creates = [l for l in lignes_nft(t) if l.startswith("create element")]
    exiger(f, len(creates) == 2, f"course avant la transaction : {len(creates)} poses exclusives, attendu 2")
    exiger(f, lignes_nft(t).count("-f -") == 1, "course avant la transaction : transaction rejouée")
    verdict_est(f, t, 942, "done", PHRASE_POSE)
    return f


def s_nft_transaction_refusee_dite(script):
    """La transaction d'allongement refusée pour une autre cause : `failed`, dit, aucune reprise."""
    t = jouer_nft(script, [ban(943, "203.0.113.43", 600)], presents=[("203.0.113.43", "reste:1s")],
                  env_plus={"NFT_TX": "refus"})
    f = []
    exiger(f, len([l for l in lignes_nft(t) if l.startswith("create element")]) == 1, "transaction refusée : reprise de la pose")
    verdict_est(f, t, 943, "failed", PHRASE_TX_REFUSEE, "Device or resource busy")
    return f


def s_nft_pose_exclusive_refusee_autrement(script):
    """La pose exclusive refusée pour une autre cause que la présence (droit, ensemble absent, délai refusé) : ni
    lecture, ni transaction, ni reprise ; `failed` qui cite l'erreur de nft — jamais un `done` sur rien de posé."""
    t = jouer_nft(script, [ban(946, "203.0.113.46", 600)], env_plus={"NFT_CREATE_REFUS": "203.0.113.46"})
    f = []
    attendu = ["list table inet plume", "list set inet plume blocklist_ttl",
               "create element inet plume blocklist_ttl { 203.0.113.46 timeout 600s }"]
    exiger(f, lignes_nft(t) == attendu, f"pose refusée autrement : commandes nft {lignes_nft(t)!r}, attendu {attendu!r}")
    verdict_est(f, t, 946, "failed", "Operation not permitted")
    return f


def s_nft_simulation_ne_promet_pas(script):
    """Le dry-run nft ne lit pas l'état : il dit que la durée ne s'applique que si elle allonge, et ne pose rien."""
    t = jouer_nft(script, [ban(944, "203.0.113.44", 10)], presents=[("203.0.113.44", "reste:9m59s990ms")],
                  env_plus={"PLUME_RESPONDER_APPLY": "0"})
    f = []
    exiger(f, not POSE_NFT.search(t.trace("nft")) and "get element" not in t.trace("nft"),
           f"une simulation a touché nft : {t.trace('nft')!r}")
    verdict_est(f, t, 944, "dryrun", "[dry-run] nft create element inet plume blocklist_ttl { 203.0.113.44 timeout 10s }",
                "deja banni : duree appliquee seulement si elle allonge, jamais raccourci")
    # `nft add element` REMPLACE le délai d'une adresse présente : un plan qui le nommerait promettrait le raccourcissement.
    exiger(f, "add element" not in t.verdicts.get(944, {}).get("result", ""), "le plan simulé nomme `add element`")
    return f


DUREES_DESORDONNEES = ["1h1h", "30s1d", "1d1d", "30m1h", "1m1h", "5s5s", "1m1m"]
DUREES_MESUREES = ["0h30m", "1d2h", "1d0s", "365d", "31536000s"]


def s_duree_desordonnee_refusee(script):
    """Une unité répétée ou désordonnée (que nft refuse en erreur de syntaxe) est refusée sur nft avec SA cause :
    rien ne part."""
    f = []
    for n, valeur in enumerate(DUREES_DESORDONNEES):
        i = 950 + 2 * n
        c = Central("tsv", [ban(i, f"198.51.100.{60 + n}")])
        try:
            t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",),
                      env_plus={"PLUME_BAN_DURATION": valeur, "NFT_ETAT": "equipe"})
        finally:
            c.fermer()
        exiger(f, not POSE_NFT.search(t.trace("nft")), f"nft `{valeur}` : passé à l'outil : {t.trace('nft')!r}")
        verdict_est(f, t, i, "failed", CAUSE_DESORDRE)
    return f


def s_cscli_garde_sa_regle_de_duree(script):
    """La règle d'ordre des unités est celle de l'analyseur de NFT : cscli garde la règle d'avant, une unité répétée
    ou désordonnée lui part TELLE QUELLE (son analyseur juge, son refus revient dans le verdict)."""
    f = []
    for n, valeur in enumerate(DUREES_DESORDONNEES):
        i = 951 + 2 * n
        ip = f"198.51.100.{60 + n}"
        c = Central("tsv", [ban(i, ip)])
        try:
            t = jouer(script, c, lecteurs=(), backend="crowdsec", bouchons=("cscli",),
                      env_plus={"PLUME_BAN_DURATION": valeur})
        finally:
            c.fermer()
        exiger(f, t.trace("cscli") == f"decisions add -i {ip} -d {valeur} -t ban -R plume-playbook\n",
               f"cscli `{valeur}` : commande changée ou refusée : {t.trace('cscli')!r}")
        verdict_est(f, t, i, "done")
    return f


def s_duree_mesuree_admise(script):
    """Les formes admises AVANT et acceptées par nft (mesuré) restent admises, sur nft comme sur CrowdSec."""
    f = []
    for n, valeur in enumerate(DUREES_MESUREES):
        ip = f"198.51.100.{80 + n}"
        for backend, bouchon in (("nft", "nft"), ("crowdsec", "cscli")):
            i = 970 + 2 * n + (backend == "crowdsec")
            c = Central("tsv", [ban(i, ip)])
            try:
                t = jouer(script, c, lecteurs=(), backend=backend, bouchons=(bouchon,),
                          env_plus={"PLUME_BAN_DURATION": valeur, "NFT_ETAT": "equipe"})
            finally:
                c.fermer()
            if backend == "nft":
                exiger(f, f"create element inet plume blocklist_ttl {{ {ip} timeout {valeur} }}" in t.trace("nft"),
                       f"nft `{valeur}` refusé : {t.trace('nft')!r}")
            else:
                exiger(f, t.trace("cscli") == f"decisions add -i {ip} -d {valeur} -t ban -R plume-playbook\n",
                       f"cscli `{valeur}` : commande changée : {t.trace('cscli')!r}")
            verdict_est(f, t, i, "done")
    return f


def s_nft_element_sans_fin_conserve(script):
    """Un élément SANS FIN déjà dans le set à durée (ni `timeout` ni `expires`, forme mesurée d'une pose sans délai) :
    son reste est infini, donc au moins égal à toute durée demandée, la plus longue servie comprise. Rien n'est récrit,
    verdict `done` avec la phrase PROPRE à ce cas — ni la phrase d'un reste fini, ni l'échec d'un reste illisible."""
    cas = [(985, "203.0.113.51", 10), (986, "203.0.113.52", BORNE)]
    t = jouer_nft(script, [ban(i, ip, d) for i, ip, d in cas], presents=[(ip, "sans_fin") for _, ip, _ in cas])
    f = []
    attendu = []
    for _, ip, d in cas:
        attendu += ["list table inet plume", "list set inet plume blocklist_ttl",
                    f"create element inet plume blocklist_ttl {{ {ip} timeout {d}s }}",
                    f"get element inet plume blocklist_ttl {{ {ip} }}"]
    exiger(f, lignes_nft(t) == attendu, f"élément sans fin : commandes nft {lignes_nft(t)!r}, attendu {attendu!r}")
    for i, _, d in cas:
        verdict_est(f, t, i, "done", PHRASE_CONSERVE_SANS_FIN, f"element sans expiration dans blocklist_ttl, {d}s demandes")
        execution_dit(f, t, i, PHRASE_CONSERVE_SANS_FIN)
        r = t.verdicts.get(i, {}).get("result", "")
        exiger(f, PHRASE_CONSERVE not in r and PHRASE_NON_APPLIQUEE not in r,
               f"#{i} : l'élément sans fin est dit comme un reste fini ou illisible : {r[:300]!r}")
    return f


def s_nft_simulation_refuse_l_unite_repetee(script):
    """Le dry-run nft juge la durée avec la règle de NFT : `1h1h` (que nft refuse) rend NON-APPLIQUE avec la cause de
    désordre, jamais la promesse d'une commande que le passage réel refuserait ; rien ne touche nft."""
    c = Central("tsv", [ban(987, "203.0.113.53")])
    try:
        t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",),
                  env_plus={"PLUME_BAN_DURATION": "1h1h", "PLUME_RESPONDER_APPLY": "0", "NFT_ETAT": "equipe"})
    finally:
        c.fermer()
    f = []
    exiger(f, t.trace("nft") == "", f"une simulation a touché nft : {t.trace('nft')!r}")
    verdict_est(f, t, 987, "dryrun", "[dry-run] NON-APPLIQUE nft", CAUSE_DESORDRE)
    exiger(f, "create element" not in t.verdicts.get(987, {}).get("result", ""),
           f"le plan simulé promet une pose refusée par nft : {t.verdicts.get(987, {}).get('result', '')[:300]!r}")
    return f


def s_plan_cscli_nomme_la_commande_jouee(script):
    """Sur crowdsec, `1h1h` part à cscli telle quelle (règle d'avant) : le résultat remis COMMENCE par la commande
    réellement jouée, à l'exécution comme en simulation — jamais « NON-APPLIQUE … aucun ban pose » quand cscli pose."""
    f = []
    for i, appliquer in ((988, "1"), (989, "0")):
        ip = f"203.0.113.{i - 910}"
        c = Central("tsv", [ban(i, ip)])
        try:
            t = jouer(script, c, lecteurs=(), backend="crowdsec", bouchons=("cscli",),
                      env_plus={"PLUME_BAN_DURATION": "1h1h", "PLUME_RESPONDER_APPLY": appliquer})
        finally:
            c.fermer()
        commande = f"cscli decisions add -i {ip} -d 1h1h -t ban -R plume-playbook"
        r = t.verdicts.get(i, {}).get("result", "")
        if appliquer == "1":
            verdict_est(f, t, i, "done")
            exiger(f, r.startswith(commande), f"#{i} : le résultat ne commence pas par la commande jouée : {r[:300]!r}")
            exiger(f, t.trace("cscli") == f"decisions add -i {ip} -d 1h1h -t ban -R plume-playbook\n",
                   f"#{i} : cscli n'a pas reçu la commande : {t.trace('cscli')!r}")
        else:
            verdict_est(f, t, i, "dryrun")
            exiger(f, r.startswith(f"[dry-run] {commande}"), f"#{i} : le plan simulé ne nomme pas la commande : {r[:300]!r}")
            exiger(f, t.trace("cscli") == "", f"#{i} : une simulation a appliqué un ban : {t.trace('cscli')!r}")
        exiger(f, "NON-APPLIQUE" not in r, f"#{i} : le résultat dit NON-APPLIQUE alors que cscli pose : {r[:300]!r}")
    return f


def s_nft_locale_traduite(script):
    """Hôte en locale française (`LANG=fr_FR.UTF-8`) : nft cite `strerror` traduit. Le répondeur pose `LC_ALL=C` sur
    ses appels : la présence (« File exists ») et l'absence à la lecture (« No such file or directory ») restent
    reconnues — un ban conservé est dit conservé, une expiration avant la lecture repose le ban, une fois."""
    t = jouer_nft(script, [ban(990, "203.0.113.56", 10), ban(991, "203.0.113.57", 600)],
                  presents=[("203.0.113.56", "reste:9m59s990ms"), ("203.0.113.57", "expire_a_la_lecture")],
                  env_plus={"LANG": "fr_FR.UTF-8"})
    f = []
    verdict_est(f, t, 990, "done", PHRASE_CONSERVE, "reste 9m59s990ms >= 10s")
    verdict_est(f, t, 991, "done", PHRASE_POSE)
    creates = [l for l in lignes_nft(t) if l.startswith("create element") and " 203.0.113.57 " in l]
    exiger(f, len(creates) == 2, f"locale traduite : {len(creates)} poses exclusives pour 203.0.113.57, attendu 2")
    exiger(f, not [l for l in lignes_nft(t) if l == "-f -" or l.startswith(("add element", "delete element"))],
           f"locale traduite : une commande récrit un ban : {lignes_nft(t)!r}")
    return f


# ----------------------------------------------------------------------------------------------------------
# `P11.25-a` — LA LEVÉE nft SUIT LA RÈGLE DU DÉMON (`classer_le_retrait_nft`, `verdict_des_deux_retraits_nft`) : chaque
# retrait est classé retiré / absent / refusé sur sa SEULE sortie d'erreur, lue sous `LC_ALL=C` ; un refus rend la
# levée `failed` quoi qu'aient rendu les autres backends ; nft seul sans aucun retrait -> `failed` ; nft sans retrait
# mais fail2ban présent -> `done` (leurs codes ne sont pas mesurés). Chaque résultat est comparé ENTIER.
# ----------------------------------------------------------------------------------------------------------
CARETS_D_ABSENCE = re.search(r"absence\(\) \{ printf 'Error: Could not process rule: %s\\n%s\\n(\^+)\\n'", BOUCHON_NFT).group(1)
# La borne d'une part de refus, recopiée de respond.sh (`NFT_PART_DE_RETRAIT_OCTETS`) : la changer là-bas rougit ici.
PART_DE_RETRAIT_OCTETS = 120
REFUS_ECRIT = "Error: Could not process rule: Operation not permitted"
LEVEE_NON_FAITE = " ; LEVEE NON FAITE : adresse absente de chaque set nft tente, rien n a ete retire"


def plan_de_levee(ip):
    return f"unban {ip} (best-effort: fail2ban tous jails + cscli + nft plume)"


def absence_ecrite(ensemble, ip):
    """Ce que le bouchon écrit pour une adresse absente, tel que le résultat le porte (sauts de ligne en espaces)."""
    return f"Error: Could not process rule: No such file or directory delete element inet plume {ensemble} {{ {ip} }} {CARETS_D_ABSENCE}"


def refus_remis(ensemble, cause, ecrit):
    return f"REFUS du retrait dans {ensemble} ({cause}) : {ecrit}"


def jouer_la_levee(script, actions, retraits, etat="equipe", bouchons=("nft",), env_plus=None):
    env = {"NFT_ETAT": etat, "NFT_RETRAITS": " ".join(f"{e}:{ip}={m}" for e, ip, m in retraits)}
    env.update(env_plus or {})
    c = Central("demon", actions)
    try:
        return jouer(script, c, lecteurs=("python3",), backend="nft", bouchons=bouchons, env_plus=env)
    finally:
        c.fermer()


def resultat_entier(fautes, t, i, statut, attendu):
    v = t.verdicts.get(i)
    if v is None:
        fautes.append(f"#{i} : aucun verdict remis (stderr={t.stderr[-400:]!r})")
        return
    exiger(fautes, v["status"] == statut, f"#{i} : statut {v['status']!r}, attendu {statut!r} ({v['result'][:500]!r})")
    exiger(fautes, v["result"] == attendu, f"#{i} : résultat {v['result']!r}, attendu {attendu!r}")


def s_levee_refusee_sur_le_set_permanent(script):
    """Retrait REFUSÉ sur `blocklist` (droit refusé), retiré sur `blocklist_ttl` : `failed`, le refus nomme le set."""
    ip = "198.51.100.61"
    t = jouer_la_levee(script, [unban(1101, ip)], [("blocklist", ip, "refus")])
    f = []
    resultat_entier(f, t, 1101, "failed", f"{plan_de_levee(ip)} |  [nft]"
                    + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist {{ {ip} }}")
                    + " [nft-ttl]")
    return f


def s_levee_refusee_sur_le_set_a_duree(script):
    """Retiré sur `blocklist`, REFUSÉ sur `blocklist_ttl` : `failed` — le second set est classé, pas seulement tenté."""
    ip = "198.51.100.62"
    t = jouer_la_levee(script, [unban(1102, ip)], [("blocklist_ttl", ip, "refus")])
    f = []
    resultat_entier(f, t, 1102, "failed", f"{plan_de_levee(ip)} |  [nft] [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist_ttl {{ {ip} }}"))
    return f


def s_levee_refusee_sur_les_deux_sets(script):
    ip = "198.51.100.63"
    t = jouer_la_levee(script, [unban(1103, ip)], [("blocklist", ip, "refus"), ("blocklist_ttl", ip, "refus")])
    f = []
    resultat_entier(f, t, 1103, "failed", f"{plan_de_levee(ip)} |  [nft]"
                    + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist {{ {ip} }}")
                    + " [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist_ttl {{ {ip} }}"))
    return f


def s_levee_absente_et_retiree(script):
    """Absent d'un set, retiré de l'autre, dans les DEUX ordres : `done`, texte d'avant à l'octet."""
    a, b = "198.51.100.64", "198.51.100.65"
    t = jouer_la_levee(script, [unban(1104, a), unban(1105, b)], [("blocklist", a, "absent"), ("blocklist_ttl", b, "absent")])
    f = []
    resultat_entier(f, t, 1104, "done", f"{plan_de_levee(a)} |  [nft]{absence_ecrite('blocklist', a)} [nft-ttl]")
    resultat_entier(f, t, 1105, "done", f"{plan_de_levee(b)} |  [nft] [nft-ttl]{absence_ecrite('blocklist_ttl', b)}")
    return f


def s_levee_deux_absences_nft_seul(script):
    """nft seul backend, adresse absente des deux sets — puis, sur un hôte sans set à durée, absente du seul set tenté :
    `failed`, LEVÉE NON FAITE (rien n a été retiré). Le retrait du set à durée inexistant n'est pas tenté."""
    a, b = "198.51.100.66", "198.51.100.76"
    t = jouer_la_levee(script, [unban(1106, a)], [("blocklist", a, "absent"), ("blocklist_ttl", a, "absent")])
    f = []
    resultat_entier(f, t, 1106, "failed", f"{plan_de_levee(a)} |  [nft]{absence_ecrite('blocklist', a)} "
                    f"[nft-ttl]{absence_ecrite('blocklist_ttl', a)}{LEVEE_NON_FAITE}")
    t = jouer_la_levee(script, [unban(1116, b)], [("blocklist", b, "absent")], etat="ancien")
    resultat_entier(f, t, 1116, "failed", f"{plan_de_levee(b)} |  [nft]{absence_ecrite('blocklist', b)}{LEVEE_NON_FAITE}")
    exiger(f, "delete element inet plume blocklist_ttl" not in t.trace("nft"),
           f"set à durée inexistant : son retrait est tenté : {t.trace('nft')!r}")
    return f


def s_levee_nft_tue_par_un_signal(script):
    """`blocklist_ttl` : nft écrit l'absence PUIS est tué par SIGKILL — un refus (code 137), jamais une absence ; le
    résultat dit le signal."""
    ip = "198.51.100.67"
    t = jouer_la_levee(script, [unban(1107, ip)], [("blocklist_ttl", ip, "signal")])
    f = []
    resultat_entier(f, t, 1107, "failed", f"{plan_de_levee(ip)} |  [nft] [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 137, nft interrompu par le signal 9",
                                  "Error: Could not process rule: No such file or directory"))
    return f


def s_levee_refusee_avec_fail2ban(script):
    """fail2ban présent (bouchon : réussit sans rien dire), refus sur `blocklist` : `failed` quand même."""
    ip = "198.51.100.68"
    t = jouer_la_levee(script, [unban(1108, ip)], [("blocklist", ip, "refus")], bouchons=("nft", "fail2ban-client"))
    f = []
    exiger(f, f"unban {ip}" in t.trace("fail2ban-client"), f"fail2ban non tenté : {t.trace('fail2ban-client')!r}")
    resultat_entier(f, t, 1108, "failed", f"{plan_de_levee(ip)} |  [f2b] [nft]"
                    + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist {{ {ip} }}")
                    + " [nft-ttl]")
    return f


def s_levee_deux_absences_avec_fail2ban_ou_crowdsec(script):
    """DÉCISION (point B) : nft n'a rien retiré mais fail2ban, puis CrowdSec, était présent ; leur code n'est pas mesuré
    -> `done` comme avant, texte d'avant à l'octet."""
    ip = "198.51.100.69"
    f = []
    for i, bouchon, etiquette in ((1109, "fail2ban-client", "[f2b]"), (1120, "cscli", "[cs]")):
        t = jouer_la_levee(script, [unban(i, ip)], [("blocklist", ip, "absent"), ("blocklist_ttl", ip, "absent")],
                           bouchons=("nft", bouchon))
        exiger(f, ip in t.trace(bouchon), f"#{i} : {bouchon} non tenté : {t.trace(bouchon)!r}")
        resultat_entier(f, t, i, "done", f"{plan_de_levee(ip)} |  {etiquette} [nft]{absence_ecrite('blocklist', ip)} "
                        f"[nft-ttl]{absence_ecrite('blocklist_ttl', ip)}")
    return f


def s_levee_bord_des_codes(script):
    """Le message d'absence sur la sortie d'erreur, code par code : 125 -> absente (`done`, l'autre set retiré) ;
    126 et 127 (commande qui ne part pas) -> refus ; 128 -> refus sans signal ; 129 -> refus dit interrompu par le
    signal 1."""
    f = []
    actions, retraits = [], []
    for k, code in enumerate((125, 126, 127, 128, 129)):
        ip = f"198.51.100.{77 + k}"
        actions.append(unban(1121 + k, ip))
        retraits.append(("blocklist", ip, f"absent_code:{code}"))
    t = jouer_la_levee(script, actions, retraits)
    ecrit = "Error: Could not process rule: No such file or directory"
    resultat_entier(f, t, 1121, "done", f"{plan_de_levee('198.51.100.77')} |  [nft]{ecrit} [nft-ttl]")
    for k, cause in ((1, "code 126"), (2, "code 127"), (3, "code 128"), (4, "code 129, nft interrompu par le signal 1")):
        resultat_entier(f, t, 1121 + k, "failed", f"{plan_de_levee(f'198.51.100.{77 + k}')} |  [nft]"
                        + refus_remis("blocklist", cause, ecrit) + " [nft-ttl]")
    return f


def s_levee_absence_sur_la_sortie_standard(script):
    """`blocklist` : l'absence écrite sur la sortie STANDARD, un refus sur la sortie d'erreur -> refus, `failed` ; la
    sortie standard part au journal de l'unité (stderr du script), jamais dans la décision."""
    ip = "198.51.100.70"
    t = jouer_la_levee(script, [unban(1110, ip)], [("blocklist", ip, "stdout_absent")])
    f = []
    resultat_entier(f, t, 1110, "failed", f"{plan_de_levee(ip)} |  [nft]"
                    + refus_remis("blocklist", "code 1", "Error: Could not process rule: Device or resource busy") + " [nft-ttl]")
    exiger(f, "Error: Could not process rule: No such file or directory" in t.stderr,
           f"la sortie standard de nft n'atteint pas le journal : {t.stderr[-400:]!r}")
    return f


def s_levee_sous_une_locale_traduite(script):
    """Hôte sous `LC_ALL=fr_FR.UTF-8` : l'absence est reconnue parce que le retrait est lancé sous `LC_ALL=C`."""
    ip = "198.51.100.71"
    t = jouer_la_levee(script, [unban(1111, ip)], [("blocklist", ip, "absent")], env_plus={"LC_ALL": "fr_FR.UTF-8"})
    f = []
    resultat_entier(f, t, 1111, "done", f"{plan_de_levee(ip)} |  [nft]{absence_ecrite('blocklist', ip)} [nft-ttl]")
    return f


def s_levee_refus_bavard_borne(script):
    """Deux refus dont la sortie est longue et sur plusieurs lignes (caractères de deux octets, chaque ligne suivante
    plus courte que la borne, la borne tombant AU MILIEU d'un caractère de la première) : chaque part est mise sur une
    ligne, coupée sur un caractère, `[...]` dit la coupe, le second set reste nommé, et le résultat entier tient sous
    la borne de 500 caractères du central. La sortie porte aussi des caractères de contrôle autres que le saut de
    ligne (échappement de couleur, cloche) : chacun devient une espace — le résultat part en JSON, où un caractère de
    contrôle brut fait refuser le corps par le central, et le verdict ne serait jamais remis."""
    ip = "198.51.100.72"
    bavard = "\x1b[31m\x07" + ("é" * 40 + "\n") * 5
    ecrit = re.sub(r"[\x00-\x1f]", " ", f"{REFUS_ECRIT} {bavard}".rstrip("\n"))
    brut = ecrit.encode("utf-8")[:PART_DE_RETRAIT_OCTETS]
    f = []
    try:
        brut.decode("utf-8")
        f.append("fixture : la borne ne tombe pas au milieu d'un caractère, la coupe sur caractère n'est pas éprouvée")
    except UnicodeDecodeError:
        pass
    coupe = brut.decode("utf-8", "ignore") + " [...]"
    t = jouer_la_levee(script, [unban(1112, ip)], [("blocklist", ip, "bavard"), ("blocklist_ttl", ip, "bavard")],
                       env_plus={"NFT_BAVARD": bavard})
    attendu = (f"{plan_de_levee(ip)} |  [nft]" + refus_remis("blocklist", "code 1", coupe)
               + " [nft-ttl]" + refus_remis("blocklist_ttl", "code 1", coupe))
    resultat_entier(f, t, 1112, "failed", attendu)
    exiger(f, len(attendu) <= 500, f"fixture : le résultat attendu dépasse la borne du central ({len(attendu)})")
    return f


def s_levee_sans_table_ni_set(script):
    """Table `inet plume` absente, nft seul : rien n'est tenté (aucun retrait), `aucun backend de ban disponible`
    comme avant ; table présente sans set à durée : seul `blocklist` est tenté, retiré -> `done`."""
    a, b = "198.51.100.73", "198.51.100.74"
    f = []
    t = jouer_la_levee(script, [unban(1113, a)], [], etat="neuf")
    resultat_entier(f, t, 1113, "failed", f"{plan_de_levee(a)} | aucun backend de ban disponible")
    exiger(f, "delete element" not in t.trace("nft"), f"table absente : un retrait est tenté : {t.trace('nft')!r}")
    t = jouer_la_levee(script, [unban(1114, b)], [], etat="ancien")
    resultat_entier(f, t, 1114, "done", f"{plan_de_levee(b)} |  [nft]")
    exiger(f, "delete element inet plume blocklist_ttl" not in t.trace("nft"),
           f"set à durée absent : son retrait est tenté : {t.trace('nft')!r}")
    return f


SONDE_DE_TABLE_REFUSEE = "SONDE nft REFUSEE sur la table inet plume (code 1)"
SONDE_DE_SET_REFUSEE = "SONDE nft REFUSEE sur le set blocklist_ttl (code 1)"


def s_levee_sonde_refusee(script):
    """Une sonde REFUSÉE n'est pas une absence : le retrait est tenté et son classement tranche, comme le démon qui ne
    sonde pas. Sondes de table et de set refusées, retraits réussis -> `done`, les deux retraits tentés ; mêmes sondes,
    retraits refusés, fail2ban présent -> `failed` ; sonde du set à durée seule refusée, adresse absente de `blocklist`,
    retrait à durée refusé, fail2ban présent -> `failed` ; même sonde refusée, nft seul, `blocklist` retiré, retrait à
    durée refusé -> `failed`. Chaque sonde refusée est dite au journal de l'unité."""
    f = []
    a, b, c, d = "198.51.100.91", "198.51.100.92", "198.51.100.93", "198.51.100.94"
    t = jouer_la_levee(script, [unban(1131, a)], [], env_plus={"NFT_SONDES_REFUSEES": "table set"})
    resultat_entier(f, t, 1131, "done", f"{plan_de_levee(a)} |  [nft] [nft-ttl]")
    for ensemble in ("blocklist", "blocklist_ttl"):
        exiger(f, f"delete element inet plume {ensemble} {{ {a} }}" in t.trace("nft"),
               f"#1131 : sonde refusée, retrait de {ensemble} non tenté : {t.trace('nft')!r}")
    for dite in (SONDE_DE_TABLE_REFUSEE, SONDE_DE_SET_REFUSEE):
        exiger(f, dite in t.stderr, f"#1131 : sonde refusée non dite au journal ({dite!r}) : {t.stderr[-600:]!r}")
    t = jouer_la_levee(script, [unban(1132, b)], [("blocklist", b, "refus"), ("blocklist_ttl", b, "refus")],
                       bouchons=("nft", "fail2ban-client"), env_plus={"NFT_SONDES_REFUSEES": "table set"})
    resultat_entier(f, t, 1132, "failed", f"{plan_de_levee(b)} |  [f2b] [nft]"
                    + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist {{ {b} }}")
                    + " [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist_ttl {{ {b} }}"))
    t = jouer_la_levee(script, [unban(1133, c)], [("blocklist", c, "absent"), ("blocklist_ttl", c, "refus")],
                       bouchons=("nft", "fail2ban-client"), env_plus={"NFT_SONDES_REFUSEES": "set"})
    resultat_entier(f, t, 1133, "failed", f"{plan_de_levee(c)} |  [f2b] [nft]{absence_ecrite('blocklist', c)} [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist_ttl {{ {c} }}"))
    exiger(f, SONDE_DE_SET_REFUSEE in t.stderr and SONDE_DE_TABLE_REFUSEE not in t.stderr,
           f"#1133 : seule la sonde du set est refusée, le journal dit autre chose : {t.stderr[-600:]!r}")
    t = jouer_la_levee(script, [unban(1134, d)], [("blocklist_ttl", d, "refus")], env_plus={"NFT_SONDES_REFUSEES": "set"})
    resultat_entier(f, t, 1134, "failed", f"{plan_de_levee(d)} |  [nft] [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist_ttl {{ {d} }}"))
    return f


def s_levee_sonde_absente_sous_une_locale_traduite(script):
    """Hôte sous `LC_ALL=fr_FR.UTF-8`, table absente, nft seul : l'absence de la table est reconnue parce que la sonde
    est lancée sous `LC_ALL=C` -> rien n'est tenté, `aucun backend de ban disponible` comme avant ; table présente sans
    set à durée : seul `blocklist` est tenté."""
    a, b = "198.51.100.95", "198.51.100.96"
    f = []
    fr = {"LC_ALL": "fr_FR.UTF-8"}
    t = jouer_la_levee(script, [unban(1135, a)], [], etat="neuf", env_plus=fr)
    resultat_entier(f, t, 1135, "failed", f"{plan_de_levee(a)} | aucun backend de ban disponible")
    exiger(f, "delete element" not in t.trace("nft"), f"table absente : un retrait est tenté : {t.trace('nft')!r}")
    t = jouer_la_levee(script, [unban(1136, b)], [], etat="ancien", env_plus=fr)
    resultat_entier(f, t, 1136, "done", f"{plan_de_levee(b)} |  [nft]")
    exiger(f, "delete element inet plume blocklist_ttl" not in t.trace("nft"),
           f"set à durée absent : son retrait est tenté : {t.trace('nft')!r}")
    return f


def s_levee_sans_nft(script):
    """nft absent de l'hôte, fail2ban seul : nft n'est ni sondé ni tenté, la levée reste `done` comme avant — une
    commande introuvable (code 127) n'est pas un refus de retrait."""
    ip = "198.51.100.97"
    f = []
    t = jouer_la_levee(script, [unban(1137, ip)], [], bouchons=("fail2ban-client",))
    resultat_entier(f, t, 1137, "done", f"{plan_de_levee(ip)} |  [f2b]")
    return f


def s_levee_retrait_muet(script):
    """`blocklist` : `delete element` sort en code 1 SANS RIEN ÉCRIRE — un refus (code non nul sans le message, règle du
    démon), jamais une absence ni un retrait : `failed`, le refus nomme le set, le code et une sortie vide ; de même avec
    fail2ban présent."""
    a, b = "198.51.100.101", "198.51.100.102"
    f = []
    t = jouer_la_levee(script, [unban(1141, a)], [("blocklist", a, "muet")])
    resultat_entier(f, t, 1141, "failed", f"{plan_de_levee(a)} |  [nft]" + refus_remis("blocklist", "code 1", "") + " [nft-ttl]")
    t = jouer_la_levee(script, [unban(1142, b)], [("blocklist", b, "muet")], bouchons=("nft", "fail2ban-client"))
    resultat_entier(f, t, 1142, "failed", f"{plan_de_levee(b)} |  [f2b] [nft]" + refus_remis("blocklist", "code 1", "") + " [nft-ttl]")
    return f


def s_levee_sonde_muette(script):
    """Sonde de table en code 1 SANS RIEN ÉCRIRE : une sonde refusée, pas une absence — les deux retraits sont tentés,
    retirés -> `done`, la sonde refusée dite au journal ; sonde du set à durée muette, retrait à durée refusé -> `failed`."""
    a, b = "198.51.100.103", "198.51.100.104"
    f = []
    t = jouer_la_levee(script, [unban(1143, a)], [], env_plus={"NFT_SONDE_TABLE": "muet"})
    resultat_entier(f, t, 1143, "done", f"{plan_de_levee(a)} |  [nft] [nft-ttl]")
    exiger(f, "SONDE nft REFUSEE sur la table inet plume (code 1) :  ; le retrait est tente" in t.stderr,
           f"#1143 : sonde muette non dite au journal : {t.stderr[-600:]!r}")
    t = jouer_la_levee(script, [unban(1144, b)], [("blocklist_ttl", b, "refus")], env_plus={"NFT_SONDE_SET": "muet"})
    resultat_entier(f, t, 1144, "failed", f"{plan_de_levee(b)} |  [nft] [nft-ttl]"
                    + refus_remis("blocklist_ttl", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist_ttl {{ {b} }}"))
    return f


def s_levee_sonde_tuee_ou_qui_ne_part_pas(script):
    """Sonde qui écrit l'absence PUIS est tuée par SIGKILL (code 137), ou qui l'écrit et sort en code 126 : le code de la
    sonde est lu, ce n'est pas une absence — le retrait est tenté et tranche. Table tuée -> `done`, signal dit au
    journal ; table en code 126 -> `done` ; set à durée tué -> son retrait est tenté, `done`."""
    a, b, c = "198.51.100.105", "198.51.100.106", "198.51.100.107"
    f = []
    t = jouer_la_levee(script, [unban(1145, a)], [], env_plus={"NFT_SONDE_TABLE": "signal"})
    resultat_entier(f, t, 1145, "done", f"{plan_de_levee(a)} |  [nft] [nft-ttl]")
    exiger(f, "SONDE nft REFUSEE sur la table inet plume (code 137, nft interrompu par le signal 9)" in t.stderr,
           f"#1145 : sonde tuée non dite au journal : {t.stderr[-600:]!r}")
    t = jouer_la_levee(script, [unban(1146, b)], [], env_plus={"NFT_SONDE_TABLE": "code126"})
    resultat_entier(f, t, 1146, "done", f"{plan_de_levee(b)} |  [nft] [nft-ttl]")
    t = jouer_la_levee(script, [unban(1147, c)], [], env_plus={"NFT_SONDE_SET": "signal"})
    resultat_entier(f, t, 1147, "done", f"{plan_de_levee(c)} |  [nft] [nft-ttl]")
    exiger(f, f"delete element inet plume blocklist_ttl {{ {c} }}" in t.trace("nft"),
           f"#1147 : sonde du set tuée, retrait à durée non tenté : {t.trace('nft')!r}")
    return f


def s_levee_sonde_absence_sur_la_sortie_standard(script):
    """Sonde de table : l'absence écrite sur la sortie STANDARD seule, « Device or resource busy » sur la sortie
    d'erreur : la sortie standard de la sonde est jetée, ce n'est pas une absence -> les retraits sont tentés, `done`."""
    ip = "198.51.100.108"
    f = []
    t = jouer_la_levee(script, [unban(1148, ip)], [], env_plus={"NFT_SONDE_TABLE": "stdout"})
    resultat_entier(f, t, 1148, "done", f"{plan_de_levee(ip)} |  [nft] [nft-ttl]")
    exiger(f, "SONDE nft REFUSEE sur la table inet plume (code 1) : Error: Could not process rule: Device or resource busy" in t.stderr,
           f"#1148 : la sonde refusée ne dit pas sa sortie d'erreur : {t.stderr[-600:]!r}")
    return f


def s_levee_refus_ne_colle_pas_a_la_levee_suivante(script):
    """Deux levées dans UN tour : la première refusée sur `blocklist`, la seconde retirée -> `failed` puis `done` ; le
    refus de la première ne reste pas acquis à la seconde."""
    a, b = "198.51.100.109", "198.51.100.110"
    t = jouer_la_levee(script, [unban(1149, a), unban(1150, b)], [("blocklist", a, "refus")])
    f = []
    resultat_entier(f, t, 1149, "failed", f"{plan_de_levee(a)} |  [nft]"
                    + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist {{ {a} }}")
                    + " [nft-ttl]")
    resultat_entier(f, t, 1150, "done", f"{plan_de_levee(b)} |  [nft] [nft-ttl]")
    return f


def s_levee_retrait_ne_colle_pas_a_la_levee_suivante(script):
    """Deux levées dans UN tour, nft seul : la première retirée, la seconde absente des deux sets -> `done` puis
    `failed`, LEVÉE NON FAITE ; le retrait de la première ne reste pas acquis à la seconde."""
    a, b = "198.51.100.111", "198.51.100.112"
    t = jouer_la_levee(script, [unban(1151, a), unban(1152, b)], [("blocklist", b, "absent"), ("blocklist_ttl", b, "absent")])
    f = []
    resultat_entier(f, t, 1151, "done", f"{plan_de_levee(a)} |  [nft] [nft-ttl]")
    resultat_entier(f, t, 1152, "failed", f"{plan_de_levee(b)} |  [nft]{absence_ecrite('blocklist', b)} "
                    f"[nft-ttl]{absence_ecrite('blocklist_ttl', b)}{LEVEE_NON_FAITE}")
    return f


def s_levee_refus_au_separateur_d_unite(script):
    """Refus dont la sortie porte \\x1f (séparateur d'unité, le HAUT de la plage des caractères de contrôle) : il devient
    une espace ; brut, il ferait refuser le corps JSON par le central et le verdict ne serait jamais remis."""
    ip = "198.51.100.113"
    t = jouer_la_levee(script, [unban(1153, ip)], [("blocklist", ip, "bavard")], env_plus={"NFT_BAVARD": "a\x1fb"})
    f = []
    resultat_entier(f, t, 1153, "failed", f"{plan_de_levee(ip)} |  [nft]" + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} a b")
                    + " [nft-ttl]")
    return f


# ----------------------------------------------------------------------------------------------------------
# `P10.21-n` — UNE RIPOSTE RE-SERVIE N'EST JAMAIS EXÉCUTÉE UNE SECONDE FOIS À L'AVEUGLE.
# Le central re-sert une riposte réclamée sans verdict au-delà de sa fenêtre de réclamation. Avant le registre
# d'exécution, l'agent la RÉEXÉCUTAIT sur cinq chemins, chacun mesuré ici par le nombre EXACT d'appels au faux nft :
# 2a arrêt brutal entre l'exécution et la retenue du verdict (ban et levée) ; 2b la retenue renonce (état non
# inscriptible, file de rejeu pleine, écriture refusée) ; 2c refus définitif du central, rejeu abandonné. Sont tenus
# aussi : la borne du registre (borne −1, borne, borne +1), l'éviction de la plus ancienne `faite`, jamais d'une
# `commencee`, la ligne illisible écartée et dite, le simulacre et les refus d'avant exécution qui n'écrivent rien,
# l'entrée retirée sur 2xx et sur `"ok":false`, gardée sur 503, l'identifiant réutilisé pour une autre riposte, chaque
# écriture refusée, et le verrou (deux exécutions simultanées, verrou orphelin repris, `flock` et repli `mkdir`).
# Phrases écrites ICI en littéral, jamais relues du script.
# ----------------------------------------------------------------------------------------------------------
REGISTRE = "ripostes-executees"
REGISTRE_BORNE = 264
REJEU_BORNE = 64
REJEU_TOURS_MAX = 5
PHRASE_REPRISE = "REPRISE d une execution interrompue (issue de la premiere inconnue)"
PHRASE_ABSENTE_APRES_INTERRUPTION = ("ADRESSE CONSTATEE ABSENTE apres une execution interrompue : retrait non observe "
                                     "(la premiere execution a pu la lever)")
CONSEQUENCE_PAS_REEXECUTEE = ("elle ne sera PAS reexecutee : le registre d execution la porte faite, son verdict "
                              "enregistre sera remis de nouveau")
CONSEQUENCE_REEXECUTEE = "elle sera REEXECUTEE (le registre d execution ne la porte pas faite)"
VERROU_DEJA_PRIS = ("respond: une autre execution de l agent tient deja le verrou : ce tour-ci ne traite RIEN "
                    "(ni rejeu, ni liste, ni remise)")
CAUSE_ID_LONG = "identifiant de plus de 19 chiffres"
SOMMEIL_INSTANTANE = {"sleep": "#!/bin/sh\nexit 0\n"}
ENSURE = ["list table inet plume", "list set inet plume blocklist_ttl"]


def j_re_remise(i, statut):
    return f"respond: #{i} NON reexecutee : deja FAITE (registre d execution), verdict enregistre RE-REMIS ({statut})"


def j_reprise(i):
    return (f"respond: #{i} REPRISE : une execution precedente a ete interrompue avant son issue (registre d "
            f"execution), la riposte est rejouee")


def j_protection_absente(i, cause):
    return (f"respond: #{i} protection contre la REEXECUTION ABSENTE pour cette riposte ({cause}) : elle est executee "
            f"quand meme (un ban est une defense, il ne se suspend pas pour un etat local)")


def j_perimee(i):
    return (f"respond: #{i} identifiant deja inscrit au registre d execution pour une AUTRE riposte (genre ou cible "
            f"differents) : entree perimee remplacee")


def j_eviction(i):
    return (f"respond: registre d execution PLEIN ({REGISTRE_BORNE} lignes) : #{i} (faite, verdict jamais pris par le "
            f"central) EVINCEE : si le central la re-sert, elle sera REEXECUTEE")


def j_illisibles(n, chemin):
    return f"respond: registre d execution : {n} ligne(s) illisible(s) ecartee(s) de {chemin}"


def j_illisibles_non_retirees(n, chemin):
    return (f"respond: registre d execution : {n} ligne(s) illisible(s) dans {chemin}, NON retiree(s) (ecriture "
            f"refusee) : elles sont ignorees a la lecture")


def j_registre_non_ordinaire(chemin):
    return f"respond: registre d execution {chemin} illisible (pas un fichier ordinaire) : ni lu ni repare ce tour-ci"


def j_faite_non_enregistree(i):
    return (f"respond: #{i} issue NON enregistree au registre d execution (ecriture refusee) : la riposte y reste "
            f"commencee ; si le central la re-sert, elle sera REPRISE")


def j_retrait_refuse(i):
    return (f"respond: #{i} verdict pris par le central, mais son entree du registre d execution n est PAS retiree "
            f"(ecriture refusee) : si le central la re-servait, son verdict enregistre serait remis de nouveau")


def j_verrou_non_pris(cause):
    return (f"respond: VERROU NON PRIS ({cause}) : ce tour-ci continue sans verrou, une execution simultanee de l agent "
            f"n est pas empechee")


def j_verrou_orphelin(chemin, porteur):
    return (f"respond: verrou ORPHELIN repris ({chemin}, porteur {porteur} disparu) : une execution precedente s est "
            f"arretee sans le rendre")


def cause_illisible(chemin):
    return f"registre d execution illisible ({chemin})"


def cause_non_inscriptible(rep):
    return f"etat local {rep} non inscriptible"


def cause_ecriture(chemin):
    return f"ecriture refusee dans {chemin}"


def cause_plein(n):
    return f"registre plein de ripostes commencees ({n} lignes pour {REGISTRE_BORNE}, une commencee ne sort jamais par eviction)"


def plan_nft_ban(ip, d):
    return (f"nft create element inet plume blocklist_ttl {{ {ip} timeout {d}s }} [duree {d}s : servie par le central] ; "
            f"deja banni : duree appliquee seulement si elle allonge, jamais raccourci")


def res_pose(ip, d):
    return f"{plan_nft_ban(ip, d)} | {PHRASE_POSE} (absente de blocklist_ttl, timeout {d}s)"


def res_conserve(ip, d, reste):
    return f"{plan_nft_ban(ip, d)} | {PHRASE_CONSERVE} (reste {reste} >= {d}s demandes), rien n est recrit"


def nft_pose(ip, d):
    return f"create element inet plume blocklist_ttl {{ {ip} timeout {d}s }}"


def nft_lecture(ip):
    return f"get element inet plume blocklist_ttl {{ {ip} }}"


def nft_levee(ip):
    return ["list table inet plume", f"delete element inet plume blocklist {{ {ip} }}",
            "list set inet plume blocklist_ttl", f"delete element inet plume blocklist_ttl {{ {ip} }}"]


def corps_attendu(i, statut, res):
    return '{"id":%s,"status":"%s","result":"%s"}' % (i, statut, res)


def remis(t, i):
    return [c for c in t.corps_remis if c.startswith('{"id":%s,' % i)]


def rep_etat(etat):
    return os.path.join(etat, "responder")


def chemin_registre(etat):
    return os.path.join(etat, "responder", REGISTRE)


def lire_registre(etat):
    p = chemin_registre(etat)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8", errors="replace") as h:
        return h.read().splitlines()


def poser_registre(etat, lignes, mode=0o600):
    os.makedirs(rep_etat(etat), mode=0o700, exist_ok=True)
    with open(chemin_registre(etat), "w", encoding="utf-8") as h:
        h.write("".join(l + "\n" for l in lignes))
    os.chmod(chemin_registre(etat), mode)


def faite(i, ip, res, genre="ban_ip", statut="done"):
    return f"{i}\tfaite\t{genre}\t{ip}\t{statut}\t{res}"


def commencee(i, ip, genre="ban_ip"):
    return f"{i}\tcommencee\t{genre}\t{ip}"


def dit(fautes, t, ligne, quoi):
    exiger(fautes, ligne in t.stderr.splitlines(), f"{quoi} : ligne absente du journal : {ligne!r} ; journal={t.stderr[-700:]!r}")


def tait(fautes, t, debut, quoi):
    trouvees = [l for l in t.stderr.splitlines() if l.startswith(debut)]
    exiger(fautes, not trouvees, f"{quoi} : {trouvees[:3]!r}")


def curl_tue_a_la_remise():
    """Un curl qui tue tout le groupe du script quand il s'apprête à REMETTRE un verdict : arrêt brutal après
    l'exécution, avant que le central n'ait rien reçu."""
    vrai = shutil.which("curl")
    return {"curl": "#!/bin/sh\ncase \"$*\" in *'/api/actions/result'*) kill -9 0 ;; esac\nexec %s \"$@\"\n" % vrai}


def tour_n(script, etat, actions, presents=(), retraits=(), statuts=(), statut=200, corps='{"ok":true}', env_plus=None,
           faux=None, fond=None, lecteurs=("python3",)):
    """Un tour nft (hôte équipé) sur l'état PARTAGÉ `etat` ; l'état de l'hôte (adresses présentes, issue des retraits)
    est posé par le scénario à chaque tour."""
    env = {"NFT_ETAT": "equipe", "NFT_PRESENTS": " ".join(f"{ip}={m}" for ip, m in presents),
           "NFT_RETRAITS": " ".join(f"{e}:{ip}={m}" for e, ip, m in retraits)}
    env.update(env_plus or {})
    c = Central("demon", actions, statuts_remise=statuts, statut_remise=statut, corps_remise=corps)
    try:
        return jouer(script, c, lecteurs=lecteurs, backend="nft", bouchons=("nft",), env_plus=env, etat=etat,
                     faux_binaires=faux, fond=fond)
    finally:
        c.fermer()


def tue_net(fautes, t, attendu_nft, quoi):
    """Validité de l'épreuve : le tour a bien été arrêté brutalement, sans aucune remise, après ces commandes nft."""
    exiger(fautes, t.rc == -9 and t.nb_verdicts == 0 and lignes_nft(t) == attendu_nft,
           f"instrument ({quoi}) : le tour devait s'arrêter brutalement après {attendu_nft!r}, sans remise : "
           f"rc={t.rc} nft={lignes_nft(t)!r} verdicts={t.nb_verdicts} {t.stderr[-300:]!r}")


def s_arret_avant_la_remise_ban(script):
    """2a, ban_ip : arrêt brutal APRÈS l'exécution, au moment de la remise. Re-servie, la riposte n'appelle PLUS nft :
    le verdict enregistré est remis à l'octet, la re-remise est dite, l'entrée part quand le central la prend."""
    i, ip = 1301, "203.0.113.131"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [ban(i, ip, 600)], faux=curl_tue_a_la_remise())
        t2 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")])
        reg = lire_registre(etat)
    f = []
    tue_net(f, t1, ENSURE + [nft_pose(ip, 600)], "2a ban")
    exiger(f, lignes_nft(t2) == [], f"2a ban : riposte REEXECUTEE au second tour : nft={lignes_nft(t2)!r}")
    exiger(f, remis(t2, i) == [corps_attendu(i, "done", res_pose(ip, 600))], f"2a ban : verdict re-remis {remis(t2, i)!r}")
    dit(f, t2, j_re_remise(i, "done"), "2a ban, re-remise")
    exiger(f, reg == [], f"2a ban : le central a pris le verdict, l'entrée doit quitter le registre : {reg!r}")
    return f


def s_arret_avant_la_remise_levee(script):
    """2a, unban_ip : arrêt brutal après la levée, au moment de la remise. Re-servie, la levée n'est PAS rejouée
    (elle rendrait LEVEE NON FAITE et contredirait le premier verdict) : le verdict enregistré est re-remis."""
    i, ip = 1302, "198.51.100.132"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [unban(i, ip)], faux=curl_tue_a_la_remise())
        reg1 = lire_registre(etat)
        t2 = tour_n(script, etat, [unban(i, ip)], retraits=[("blocklist", ip, "absent"), ("blocklist_ttl", ip, "absent")])
    f = []
    tue_net(f, t1, nft_levee(ip), "2a levée")
    attendu = f"{plan_de_levee(ip)} |  [nft] [nft-ttl]"
    exiger(f, reg1 == [faite(i, ip, attendu, genre="unban_ip")], f"2a levée : registre après l'exécution {reg1!r}")
    exiger(f, lignes_nft(t2) == [], f"2a levée : levée REEXECUTEE au second tour : nft={lignes_nft(t2)!r}")
    exiger(f, remis(t2, i) == [corps_attendu(i, "done", attendu)], f"2a levée : verdict re-remis {remis(t2, i)!r}")
    dit(f, t2, j_re_remise(i, "done"), "2a levée, re-remise")
    return f


def s_arret_pendant_la_levee(script):
    """2a, unban_ip : arrêt brutal PENDANT la levée (registre `commencee`). Re-servie, elle est REPRISE par les mêmes
    commandes, une fois chacune ; l'adresse constatée absente partout est rendue `done` avec le texte de reprise, et le
    verrou laissé par l'arrêt brutal est repris (il n'empêche pas le tour)."""
    i, ip = 1303, "198.51.100.133"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [unban(i, ip)], env_plus={"NFT_TUER_SUR": "delete element inet plume blocklist_ttl*"})
        reg1 = lire_registre(etat)
        porteur_lu = os.path.join(rep_etat(etat), "verrou.d", "porteur")
        porteur = open(porteur_lu).read().split()[0] if os.path.exists(porteur_lu) else None
        t2 = tour_n(script, etat, [unban(i, ip)], retraits=[("blocklist", ip, "absent"), ("blocklist_ttl", ip, "absent")])
        reg2 = lire_registre(etat)
        verrou_apres = os.path.exists(os.path.join(rep_etat(etat), "verrou.d"))
    f = []
    tue_net(f, t1, nft_levee(ip), "2a levée interrompue")
    exiger(f, reg1 == [commencee(i, ip, genre="unban_ip")], f"2a levée interrompue : registre {reg1!r}")
    exiger(f, lignes_nft(t2) == nft_levee(ip), f"2a levée interrompue : reprise {lignes_nft(t2)!r}")
    resultat_entier(f, t2, i, "done", f"{PHRASE_REPRISE} : {plan_de_levee(ip)} |  [nft]{absence_ecrite('blocklist', ip)} "
                    f"[nft-ttl]{absence_ecrite('blocklist_ttl', ip)} ; {PHRASE_ABSENTE_APRES_INTERRUPTION}")
    dit(f, t2, j_reprise(i), "2a levée interrompue, reprise")
    dit(f, t2, j_verrou_orphelin(os.path.join(rep_etat(etat), "verrou.d"), f"pid {porteur}"), "verrou laissé par l'arrêt brutal")
    exiger(f, reg2 == [] and not verrou_apres, f"2a levée interrompue : registre {reg2!r}, verrou rendu={not verrou_apres}")
    return f


def s_arret_pendant_la_pose(script):
    """2a, ban_ip : arrêt brutal PENDANT la pose (registre `commencee`). Reprise par le même `enforce` : la pose
    exclusive est refusée (l'adresse est là), le reste est lu, rien n'est recrit ; le résultat dit la reprise."""
    i, ip = 1304, "203.0.113.134"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [ban(i, ip, 600)], env_plus={"NFT_TUER_SUR": "create element*"})
        reg1 = lire_registre(etat)
        t2 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")])
    f = []
    tue_net(f, t1, ENSURE + [nft_pose(ip, 600)], "2a pose interrompue")
    exiger(f, reg1 == [commencee(i, ip)], f"2a pose interrompue : registre {reg1!r}")
    exiger(f, lignes_nft(t2) == ENSURE + [nft_pose(ip, 600), nft_lecture(ip)], f"2a pose interrompue : {lignes_nft(t2)!r}")
    resultat_entier(f, t2, i, "done", f"{PHRASE_REPRISE} : {res_conserve(ip, 600, '59m59s990ms')}")
    dit(f, t2, j_reprise(i), "2a pose interrompue, reprise")
    return f


def s_levee_refusee_a_la_reprise(script):
    """Reprise d'une levée interrompue : un REFUS de retrait reste `failed`, texte de reprise compris. Une levée
    PRÉCÈDE la reprise dans le même tour et ne retire rien (nft seul) : le constat « rien retiré » de la première
    ne déteint pas sur la reprise refusée."""
    i, ip = 1305, "198.51.100.135"
    i0, ip0 = 1306, "198.51.100.136"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [commencee(i, ip, genre="unban_ip")])
        t = tour_n(script, etat, [unban(i0, ip0), unban(i, ip)],
                   retraits=[("blocklist", ip0, "absent"), ("blocklist_ttl", ip0, "absent"),
                             ("blocklist", ip, "refus"), ("blocklist_ttl", ip, "absent")])
    f = []
    verdict_est(f, t, i0, "failed", "LEVEE NON FAITE")
    resultat_entier(f, t, i, "failed", f"{PHRASE_REPRISE} : {plan_de_levee(ip)} |  [nft]"
                    + refus_remis("blocklist", "code 1", f"{REFUS_ECRIT} delete element inet plume blocklist {{ {ip} }}")
                    + f" [nft-ttl]{absence_ecrite('blocklist_ttl', ip)}")
    return f


def s_etat_non_inscriptible(script):
    """2b, état local non inscriptible (ni rejeu, ni registre, ni verrou possibles) : la riposte est EXÉCUTÉE quand
    même à chaque tour — la défense ne se suspend pas — et chaque tour avoue que la protection est absente et
    qu'elle sera réexécutée."""
    i, ip = 1311, "203.0.113.141"
    with tempfile.TemporaryDirectory() as racine:
        open(os.path.join(racine, "fichier"), "w").close()
        etat = os.path.join(racine, "fichier", "sous")
        rep = os.path.join(etat, "responder")
        t1 = tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
        t2 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")], statut=503, faux=SOMMEIL_INSTANTANE)
    f = []
    exiger(f, lignes_nft(t1) == ENSURE + [nft_pose(ip, 600)], f"2b non inscriptible : tour 1 {lignes_nft(t1)!r}")
    exiger(f, lignes_nft(t2) == ENSURE + [nft_pose(ip, 600), nft_lecture(ip)], f"2b non inscriptible : tour 2 {lignes_nft(t2)!r}")
    exiger(f, remis(t1, i) == [corps_attendu(i, "done", res_pose(ip, 600))] * 3, f"2b non inscriptible : {remis(t1, i)!r}")
    exiger(f, remis(t2, i) == [corps_attendu(i, "done", res_conserve(ip, 600, "59m59s990ms"))] * 3,
           f"2b non inscriptible : {remis(t2, i)!r}")
    for n, t in (("1", t1), ("2", t2)):
        dit(f, t, j_verrou_non_pris(cause_non_inscriptible(rep)), f"tour {n}, verrou")
        dit(f, t, j_protection_absente(i, cause_non_inscriptible(rep)), f"tour {n}, protection")
        dit(f, t, f"respond: #{i} verdict NON RETENU pour rejeu : etat local {rep} non inscriptible — le central "
                  f"re-servira la riposte apres sa fenetre de reclamation, et {CONSEQUENCE_REEXECUTEE}", f"tour {n}, rejeu")
    return f


def jouer_deux_tours_rejeu_hostile(script, etat, i, ip):
    t1 = tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
    t2 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")], statut=503, faux=SOMMEIL_INSTANTANE)
    return t1, t2


def s_file_de_rejeu_pleine(script):
    """2b, file de rejeu PLEINE : le verdict n'est pas retenu, mais le registre porte la riposte `faite` : re-servie,
    elle n'appelle plus nft, son verdict enregistré est re-remis à l'octet, et l'aveu le dit."""
    i, ip = 1312, "203.0.113.142"
    with tempfile.TemporaryDirectory() as etat:
        os.makedirs(rep_etat(etat), mode=0o700)
        rejeu = os.path.join(rep_etat(etat), "verdicts-a-remettre")
        with open(rejeu, "w") as h:
            h.write("".join('%d\t0\t{"id":%d,"status":"done","result":"deja applique"}\n' % (2000 + k, 2000 + k)
                            for k in range(REJEU_BORNE)))
        t1, t2 = jouer_deux_tours_rejeu_hostile(script, etat, i, ip)
    f = []
    exiger(f, lignes_nft(t1) == ENSURE + [nft_pose(ip, 600)], f"2b file pleine : tour 1 {lignes_nft(t1)!r}")
    exiger(f, lignes_nft(t2) == [], f"2b file pleine : riposte REEXECUTEE au tour 2 : {lignes_nft(t2)!r}")
    corps = corps_attendu(i, "done", res_pose(ip, 600))
    exiger(f, remis(t1, i) == [corps] * 3 and remis(t2, i) == [corps] * 3,
           f"2b file pleine : remises {remis(t1, i)!r} / {remis(t2, i)!r}")
    for n, t in (("1", t1), ("2", t2)):
        dit(f, t, f"respond: #{i} verdict NON RETENU pour rejeu : la file de rejeu est PLEINE ({REJEU_BORNE} verdicts en "
                  f"attente dans {rejeu}) — le central re-servira la riposte, et {CONSEQUENCE_PAS_REEXECUTEE}", f"tour {n}")
    dit(f, t2, j_re_remise(i, "done"), "2b file pleine, re-remise")
    return f


def s_ecriture_du_rejeu_refusee(script):
    """2b, écriture du rejeu REFUSÉE (disque plein : `/dev/full`) : le registre porte la riposte `faite`, re-servie
    elle n'appelle plus nft, son verdict est re-remis à l'octet, l'aveu dit qu'elle ne sera pas réexécutée."""
    if not os.path.exists("/dev/full"):
        refuser_de_conclure("/dev/full absent : l'écriture refusée du rejeu ne peut pas être jouée")
    i, ip = 1313, "203.0.113.143"
    with tempfile.TemporaryDirectory() as etat:
        os.makedirs(rep_etat(etat), mode=0o700)
        rejeu = os.path.join(rep_etat(etat), "verdicts-a-remettre")
        os.symlink("/dev/full", rejeu)
        t1, t2 = jouer_deux_tours_rejeu_hostile(script, etat, i, ip)
    f = []
    exiger(f, lignes_nft(t1) == ENSURE + [nft_pose(ip, 600)], f"2b écriture refusée : tour 1 {lignes_nft(t1)!r}")
    exiger(f, lignes_nft(t2) == [], f"2b écriture refusée : riposte REEXECUTEE au tour 2 : {lignes_nft(t2)!r}")
    corps = corps_attendu(i, "done", res_pose(ip, 600))
    exiger(f, remis(t1, i) == [corps] * 3 and remis(t2, i) == [corps] * 3,
           f"2b écriture refusée : remises {remis(t1, i)!r} / {remis(t2, i)!r}")
    for n, t in (("1", t1), ("2", t2)):
        dit(f, t, f"respond: #{i} verdict NON RETENU pour rejeu : ecriture refusee dans {rejeu} — le central re-servira "
                  f"la riposte, et {CONSEQUENCE_PAS_REEXECUTEE}", f"tour {n}")
    return f


def s_refus_definitif_du_central(script):
    """2c, refus DÉFINITIF de la remise (400) : le verdict n'est ni retenu ni réessayé, l'entrée `faite` reste ;
    re-servie, la riposte n'appelle plus nft et son verdict est re-remis à l'octet."""
    i, ip = 1321, "203.0.113.151"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
        t2 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")], statut=400)
        reg = lire_registre(etat)
    f = []
    exiger(f, lignes_nft(t1) == ENSURE + [nft_pose(ip, 600)], f"2c refus : tour 1 {lignes_nft(t1)!r}")
    exiger(f, lignes_nft(t2) == [], f"2c refus : riposte REEXECUTEE au tour 2 : {lignes_nft(t2)!r}")
    corps = corps_attendu(i, "done", res_pose(ip, 600))
    exiger(f, remis(t1, i) == [corps] and remis(t2, i) == [corps], f"2c refus : {remis(t1, i)!r} / {remis(t2, i)!r}")
    dit(f, t2, j_re_remise(i, "done"), "2c refus, re-remise")
    exiger(f, reg == [faite(i, ip, res_pose(ip, 600))], f"2c refus : l'entrée non prise doit rester : {reg!r}")
    return f


def s_rejeu_abandonne(script):
    """2c, rejeu ABANDONNÉ au cinquième tour : l'aveu dit qu'elle ne sera pas réexécutée ; re-servie ensuite, la
    riposte n'appelle plus nft, son verdict est re-remis à l'octet, et l'entrée part quand le central la prend."""
    i, ip = 1322, "203.0.113.152"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
        vides = [tour_n(script, etat, [], statut=503, faux=SOMMEIL_INSTANTANE) for _ in range(REJEU_TOURS_MAX)]
        t7 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")])
        reg = lire_registre(etat)
    f = []
    corps = corps_attendu(i, "done", res_pose(ip, 600))
    exiger(f, lignes_nft(t1) == ENSURE + [nft_pose(ip, 600)], f"2c abandon : tour 1 {lignes_nft(t1)!r}")
    exiger(f, all(lignes_nft(v) == [] and remis(v, i) == [corps] for v in vides),
           f"2c abandon : tours de rejeu {[(lignes_nft(v), remis(v, i)) for v in vides]!r}")
    dit(f, vides[-1], f"respond: #{i} verdict ABANDONNE apres {REJEU_TOURS_MAX} tours de rejeu (dernier HTTP 503) : la "
                      f"riposte reste OUVERTE au central, qui la re-servira, et {CONSEQUENCE_PAS_REEXECUTEE} : "
                      '{"ok":true}', "2c abandon, aveu")
    exiger(f, lignes_nft(t7) == [], f"2c abandon : riposte REEXECUTEE après l'abandon : {lignes_nft(t7)!r}")
    exiger(f, remis(t7, i) == [corps], f"2c abandon : verdict re-remis {remis(t7, i)!r}")
    dit(f, t7, j_re_remise(i, "done"), "2c abandon, re-remise")
    exiger(f, reg == [], f"2c abandon : verdict pris, l'entrée doit partir : {reg!r}")
    return f


def prefill_faites(n, base=5000):
    return [faite(base + k, f"203.0.113.{k % 200 + 1}", f"deja faite {k}") for k in range(n)]


def s_registre_borne(script):
    """Borne du registre, aux trois bords : borne −1 (rien n'est évincé), borne (la plus ancienne `faite` sort),
    borne +1 (les deux plus anciennes sortent) ; chaque éviction est dite, la riposte neuve est inscrite."""
    i, ip = 1331, "203.0.113.161"
    plein = prefill_faites(REGISTRE_BORNE + 1)
    f = []
    for n, evincees in ((REGISTRE_BORNE - 1, 0), (REGISTRE_BORNE, 1), (REGISTRE_BORNE + 1, 2)):
        with tempfile.TemporaryDirectory() as etat:
            poser_registre(etat, plein[:n])
            t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
            reg = lire_registre(etat) or []
        exiger(f, reg == plein[evincees:n] + [faite(i, ip, res_pose(ip, 600))],
               f"borne, {n} lignes posées : registre de {len(reg)} lignes, tête {reg[:1]!r}, queue {reg[-1:]!r}")
        evs = [l for l in t.stderr.splitlines() if l.startswith("respond: registre d execution PLEIN")]
        exiger(f, evs == [j_eviction(5000 + k) for k in range(evincees)], f"borne, {n} lignes : évictions dites {evs!r}")
        exiger(f, lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"borne, {n} lignes : {lignes_nft(t)!r}")
    return f


def s_registre_commencees_jamais_evincees(script):
    """Une `commencee` ne sort jamais par éviction : (a) des `commencee` en tête, la plus ancienne `faite` sort ;
    (b) registre plein de `commencee` : rien ne sort, la riposte est exécutée quand même et la protection absente
    avouée ; (c) une seule `faite` pour deux places à faire : rien ne sort (tout ou rien)."""
    i, ip = 1332, "203.0.113.162"
    f = []
    tete = [commencee(6000 + k, f"198.51.100.{k + 1}") for k in range(3)]
    faites = prefill_faites(REGISTRE_BORNE - 3)
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, tete + faites)
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
        reg = lire_registre(etat) or []
    exiger(f, reg == tete + faites[1:] + [faite(i, ip, res_pose(ip, 600))], f"(a) registre : tête {reg[:4]!r}")
    dit(f, t, j_eviction(5000), "(a) éviction de la plus ancienne faite")
    toutes = [commencee(6100 + k, f"198.51.100.{k % 200 + 1}") for k in range(REGISTRE_BORNE)]
    for nom, lignes in (("b", toutes), ("c", toutes + [faite(6999, "203.0.113.9", "seule faite")])):
        with tempfile.TemporaryDirectory() as etat:
            poser_registre(etat, lignes)
            t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
            reg = lire_registre(etat)
        exiger(f, reg == lignes, f"({nom}) le registre a changé : {len(reg or [])} lignes")
        dit(f, t, j_protection_absente(i, cause_plein(len(lignes))), f"({nom}) protection absente")
        tait(f, t, "respond: registre d execution PLEIN", f"({nom}) éviction")
        exiger(f, lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"({nom}) la riposte n'est pas exécutée : {lignes_nft(t)!r}")
        verdict_est(f, t, i, "done")
    return f


def s_registre_lignes_illisibles(script):
    """Lignes illisibles EN TÊTE et AU MILIEU, lisibles derrière : elles sont écartées et dites (compte exact), les
    lignes lisibles qui suivent restent lues (la riposte `faite` placée après n'est pas réexécutée)."""
    i, ip = 1333, "203.0.113.163"
    garde = [faite(7000, "203.0.113.70", "ok 7000"), commencee(7001, "203.0.113.71")]
    lignes = ["pas une ligne du registre", garde[0], "7002\tfaite\tban_ip\t203.0.113.72\tpeut-etre\tx", garde[1],
              faite(i, ip, "verdict enregistre de 1333")]
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, lignes)
        t = tour_n(script, etat, [ban(i, ip, 600)])
        reg = lire_registre(etat)
    f = []
    dit(f, t, j_illisibles(2, chemin_registre(etat)), "lignes illisibles")
    exiger(f, lignes_nft(t) == [], f"riposte faite derrière des lignes illisibles REEXECUTEE : {lignes_nft(t)!r}")
    exiger(f, remis(t, i) == [corps_attendu(i, "done", "verdict enregistre de 1333")], f"re-remise {remis(t, i)!r}")
    exiger(f, reg == garde, f"registre après le tour : {reg!r}")
    return f


def s_simulacre_et_refus_n_ecrivent_rien(script):
    """Le simulacre et chaque refus d'avant exécution (adresse protégée, liste d'épargne, durée hors contrat, cible
    non IP) n'écrivent RIEN au registre ; seule la riposte exécutée y est inscrite."""
    ip_e = "203.0.113.166"
    actions = [ban(1341, "203.0.113.164", 600, dry=True), ban(1342, "10.0.0.5", 600), ban(1343, "203.0.113.99", 600),
               ban(1344, "203.0.113.165", 0), ban(1345, "pas-une-ip", 600), ban(1346, ip_e, 600)]
    with tempfile.TemporaryDirectory() as etat:
        t = tour_n(script, etat, actions, statut=400)
        reg = lire_registre(etat)
    f = []
    exiger(f, reg == [faite(1346, ip_e, res_pose(ip_e, 600))], f"registre : {reg!r}")
    for i, st in ((1341, "dryrun"), (1342, "failed"), (1343, "failed"), (1344, "failed"), (1345, "failed"), (1346, "done")):
        verdict_est(f, t, i, st)
    return f


def s_registre_retire_ou_garde(script):
    """L'entrée part quand le central prend le verdict (2xx) ou dit la riposte close (`"ok":false`) ; elle reste sur
    503 (et le verdict est retenu) ; le rejeu qui la remet ensuite en 2xx la retire aussi."""
    i, ip = 1351, "203.0.113.171"
    f = []
    for nom, corps in (("2xx", '{"ok":true}'), ("ok:false", '{"ok":false}')):
        with tempfile.TemporaryDirectory() as etat:
            tour_n(script, etat, [ban(i, ip, 600)], corps=corps)
            reg = lire_registre(etat)
        exiger(f, reg == [], f"{nom} : l'entrée reste au registre : {reg!r}")
    with tempfile.TemporaryDirectory() as etat:
        tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
        reg1 = lire_registre(etat)
        t2 = tour_n(script, etat, [])
        reg2 = lire_registre(etat)
    exiger(f, reg1 == [faite(i, ip, res_pose(ip, 600))], f"503 : l'entrée doit rester : {reg1!r}")
    dit(f, t2, f"respond: #{i} verdict REJOUE et remis au tour 1", "rejeu remis")
    exiger(f, reg2 == [], f"rejeu remis en 2xx : l'entrée doit partir : {reg2!r}")
    return f


def s_identifiant_reutilise(script):
    """Un identifiant inscrit pour une AUTRE riposte (cible différente, puis genre différent) n'est pas une
    re-présentation : la riposte est exécutée, l'entrée périmée remplacée (sans doublon), et c'est dit."""
    f = []
    for i, ip, vieille in ((1352, "203.0.113.172", faite(1352, "203.0.113.1", "vieux verdict")),
                           (1353, "203.0.113.173", faite(1353, "203.0.113.173", "vieille levee", genre="unban_ip"))):
        with tempfile.TemporaryDirectory() as etat:
            poser_registre(etat, [vieille])
            t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
            reg = lire_registre(etat)
        exiger(f, lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"#{i} : la riposte n'est pas exécutée : {lignes_nft(t)!r}")
        dit(f, t, j_perimee(i), f"#{i} entrée périmée")
        exiger(f, reg == [faite(i, ip, res_pose(ip, 600))], f"#{i} : registre {reg!r}")
    # Arrêt brutal après l'inscription d'un id réutilisé : la périmée PRÉCÈDE la `commencee` ; seule la DERNIÈRE ligne
    # de l'id compte -> reprise, et la `faite` finale remplace les deux.
    i, ip = 1354, "203.0.113.176"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(i, "203.0.113.2", "vieux verdict"), commencee(i, ip)])
        t = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")], statut=400)
        reg = lire_registre(etat)
    resultat_entier(f, t, i, "done", f"{PHRASE_REPRISE} : {res_conserve(ip, 600, '59m59s990ms')}")
    exiger(f, reg == [faite(i, ip, f"{PHRASE_REPRISE} : {res_conserve(ip, 600, '59m59s990ms')}")], f"#{i} : registre {reg!r}")
    return f


def s_verdict_enregistre_avant_tout_controle(script):
    """Le verdict ENREGISTRÉ est re-remis tel quel — un `failed` reste `failed` — et AVANT les contrôles d'avant
    exécution : une adresse passée depuis dans la liste d'épargne ne change pas le verdict d'une riposte faite."""
    i1, ip1, i2, ip2 = 1355, "203.0.113.177", 1356, "203.0.113.99"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(i1, ip1, "verdict en echec", statut="failed"), faite(i2, ip2, "pose avant l epargne")])
        t = tour_n(script, etat, [ban(i1, ip1, 600), ban(i2, ip2, 600)], statut=400)
    f = []
    exiger(f, remis(t, i1) == [corps_attendu(i1, "failed", "verdict en echec")], f"#{i1} : {remis(t, i1)!r}")
    exiger(f, remis(t, i2) == [corps_attendu(i2, "done", "pose avant l epargne")], f"#{i2} : {remis(t, i2)!r}")
    exiger(f, lignes_nft(t) == [], f"riposte faite réexécutée : {lignes_nft(t)!r}")
    dit(f, t, j_re_remise(i1, "failed"), "re-remise d'un échec")
    return f


def cible_et_resultat_longs():
    """Une cible IPv6 de forme acceptée (plus longue que la borne du registre) et une sortie de cscli multi-octets,
    calée pour que la coupe du résultat tombe AU MILIEU d'un caractère de deux octets."""
    sortie = "ligne1 ligne2 " + "é" * 300
    for k in range(40, 60):
        cible = "2001:db8:" + ":".join(["0"] * k) + "a"
        plan = f"cscli decisions add -i {cible} -d 600s -t ban -R plume-playbook [duree 600s : servie par le central]"
        brut = f"{plan} | {sortie}"
        if len(cible) > 64 and len(brut.encode()) > 400 and (400 - len(f"{plan} | ligne1 ligne2 ".encode())) % 2 == 1:
            return cible, brut
    refuser_de_conclure("instrument : aucune cible ne cale la coupe du résultat au milieu d'un caractère")


FAUX_CSCLI_BAVARD = r"""#!/bin/sh
printf '%s
' "$*" >> "$TRACE_ENFORCEMENT.cscli"
printf 'ligne1
ligne2 '
i=0; while [ $i -lt 300 ]; do printf '\303\251'; i=$((i+1)); done
"""


def s_ligne_du_registre_bornee(script):
    """Une ligne du registre est bornée : la cible coupée à sa borne, le résultat privé de ses caractères de contrôle
    (saut de ligne compris) et coupé à sa borne sur un caractère ENTIER ; re-servie, la riposte n'appelle plus cscli et
    son verdict re-remis est exactement ce résultat borné."""
    i = 1357
    cible, brut = cible_et_resultat_longs()
    borne = brut.encode()[:400].decode("utf-8", errors="ignore")
    tours = []
    with tempfile.TemporaryDirectory() as etat:
        for _ in range(2):
            c = Central("demon", [ban(i, cible, 600)], statut_remise=400)
            try:
                tours.append(jouer(script, c, lecteurs=("python3",), backend="crowdsec", bouchons=(),
                                   faux_binaires={"cscli": FAUX_CSCLI_BAVARD}, etat=etat))
            finally:
                c.fermer()
        reg = lire_registre(etat)
    t1, t2 = tours
    f = []
    exiger(f, t1.trace("cscli").count("decisions add") == 1, f"instrument : cscli n'a pas posé le ban : {t1.trace('cscli')!r}")
    exiger(f, reg == [f"{i}\tfaite\tban_ip\t{cible[:64]}\tdone\t{borne}"], f"ligne du registre {reg!r}")
    exiger(f, t2.trace("cscli") == "", f"riposte REEXECUTEE : {t2.trace('cscli')!r}")
    exiger(f, remis(t2, i) == [corps_attendu(i, "done", borne)], f"re-remise {[r[-40:] for r in remis(t2, i)]!r}")
    return f


def s_queue_de_zeros_lue(script):
    """Une coupure de courant laisse la fin du registre remplie d'octets NULS : la ligne `faite` qui les précède reste
    lue (re-remise, pas d'exécution), aucune ligne n'est dite illisible, et l'aveu d'une remise non retenue dit encore
    qu'elle ne sera pas réexécutée."""
    i, ip = 1358, "203.0.113.178"
    with tempfile.TemporaryDirectory() as etat:
        os.makedirs(rep_etat(etat), mode=0o700)
        with open(chemin_registre(etat), "wb") as h:
            h.write((faite(i, ip, "pose avant la coupure") + "\n").encode() + b"\0" * 64)
        os.chmod(chemin_registre(etat), 0o600)
        rejeu = os.path.join(rep_etat(etat), "verdicts-a-remettre")
        with open(rejeu, "w") as h:
            h.write("".join('%d\t0\t{"id":%d,"status":"done","result":"deja applique"}\n' % (2000 + k, 2000 + k)
                            for k in range(REJEU_BORNE)))
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
    f = []
    exiger(f, lignes_nft(t) == [], f"riposte REEXECUTEE : {lignes_nft(t)!r}")
    exiger(f, remis(t, i) == [corps_attendu(i, "done", "pose avant la coupure")] * 3, f"re-remises {remis(t, i)!r}")
    tait(f, t, "respond: registre d execution :", "lignes dites illisibles")
    dit(f, t, f"respond: #{i} verdict NON RETENU pour rejeu : la file de rejeu est PLEINE ({REJEU_BORNE} verdicts en "
              f"attente dans {rejeu}) — le central re-servira la riposte, et {CONSEQUENCE_PAS_REEXECUTEE}", "aveu")
    return f


def s_aveu_lit_la_derniere_ligne(script):
    """Id réutilisé, puis issue NON enregistrée : la périmée (`faite`, autre riposte) PRÉCÈDE la `commencee` de la
    riposte servie. L'aveu de la remise non retenue lit la DERNIÈRE ligne de l'id : la riposte sera réexécutée (reprise),
    il ne promet pas une re-remise que la lecture ne ferait pas."""
    i, ip = 1360, "203.0.113.180"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(i, "203.0.113.3", "vieux verdict")])
        os.makedirs(chemin_registre(etat) + ".nouveau")
        rejeu = os.path.join(rep_etat(etat), "verdicts-a-remettre")
        with open(rejeu, "w") as h:
            h.write("".join('%d\t0\t{"id":%d,"status":"done","result":"deja applique"}\n' % (2000 + k, 2000 + k)
                            for k in range(REJEU_BORNE)))
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
        reg = lire_registre(etat)
    f = []
    exiger(f, reg == [faite(i, "203.0.113.3", "vieux verdict"), commencee(i, ip)], f"registre {reg!r}")
    dit(f, t, j_faite_non_enregistree(i), "issue non enregistrée")
    dit(f, t, f"respond: #{i} verdict NON RETENU pour rejeu : la file de rejeu est PLEINE ({REJEU_BORNE} verdicts en "
              f"attente dans {rejeu}) — le central re-servira la riposte, et {CONSEQUENCE_REEXECUTEE}", "aveu")
    return f


def s_identifiant_trop_long(script):
    """Un identifiant de plus de 19 chiffres (file TSV) n'est pas inscrit : exécuté quand même, protection absente
    avouée ; à 19 chiffres (le bord), il est inscrit."""
    long_, bord = "12345678901234567890", "1234567890123456789"
    a, b = "203.0.113.174", "203.0.113.175"
    actions = [{"id": long_, "kind": "ban_ip", "target": a, "dry_run": False},
               {"id": bord, "kind": "ban_ip", "target": b, "dry_run": False},
               {"id": 1359, "kind": "ban ip", "target": "203.0.113.179", "dry_run": False}]
    with tempfile.TemporaryDirectory() as etat:
        t = tour_n(script, etat, actions, statut=400, lecteurs=())
        reg = lire_registre(etat) or []
        t2 = tour_n(script, etat, actions[2:], statut=400, lecteurs=())
    f = []
    dit(f, t, j_protection_absente(long_, CAUSE_ID_LONG), "identifiant trop long")
    exiger(f, [l.split("\t")[:4] for l in reg] == [[bord, "faite", "ban_ip", b], ["1359", "faite", "ban_ip", "203.0.113.179"]],
           f"registre : {reg!r}")
    # Un genre servi en TSV avec une espace est ramené à l'ASCII sans espace : la ligne reste lisible et relue.
    dit(f, t2, j_re_remise(1359, "failed"), "genre ramené à l'ASCII sans espace")
    poses = [l for l in lignes_nft(t) if l.startswith("create element")]
    exiger(f, poses == [f"create element inet plume blocklist_ttl {{ {a} timeout 7h }}",
                        f"create element inet plume blocklist_ttl {{ {b} timeout 7h }}"], f"poses : {poses!r}")
    return f


def s_ecritures_du_registre_refusees(script):
    """Chaque écriture refusée du registre : éviction (réécriture refusée) -> exécutée quand même, protection absente
    avouée, registre inchangé ; issue non enregistrée (la riposte reste `commencee`) ; retrait refusé après la prise
    du verdict ; lignes illisibles non retirées, mais ignorées à la lecture (la riposte `faite` lisible est re-remise,
    pas réexécutée)."""
    f = []
    nouveau = lambda etat: os.makedirs(chemin_registre(etat) + ".nouveau")  # noqa: E731
    i, ip = 1361, "203.0.113.181"
    with tempfile.TemporaryDirectory() as etat:
        plein = prefill_faites(REGISTRE_BORNE)
        poser_registre(etat, plein); nouveau(etat)
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
        reg = lire_registre(etat)
    dit(f, t, j_protection_absente(i, cause_ecriture(chemin_registre(etat))), "éviction refusée")
    tait(f, t, "respond: registre d execution PLEIN", "éviction refusée mais dite faite")
    exiger(f, reg == plein and lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"éviction refusée : {len(reg or [])} lignes")
    with tempfile.TemporaryDirectory() as etat:
        os.makedirs(rep_etat(etat), mode=0o700); nouveau(etat)
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
        reg = lire_registre(etat)
    dit(f, t, j_faite_non_enregistree(i), "issue non enregistrée")
    exiger(f, reg == [commencee(i, ip)], f"issue non enregistrée : {reg!r}")
    verdict_est(f, t, i, "done")
    with tempfile.TemporaryDirectory() as etat:
        enregistree = faite(i, ip, "verdict enregistre")
        poser_registre(etat, [enregistree]); nouveau(etat)
        t = tour_n(script, etat, [ban(i, ip, 600)])
        reg = lire_registre(etat)
    dit(f, t, j_retrait_refuse(i), "retrait refusé")
    exiger(f, reg == [enregistree] and lignes_nft(t) == [], f"retrait refusé : {reg!r} {lignes_nft(t)!r}")
    with tempfile.TemporaryDirectory() as etat:
        lignes = ["pas une ligne du registre", faite(i, ip, "verdict lisible"), f"{i}\tfaite\tban_ip"]
        poser_registre(etat, lignes); nouveau(etat)
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
        reg = lire_registre(etat)
    dit(f, t, j_illisibles_non_retirees(2, chemin_registre(etat)), "illisibles non retirées")
    exiger(f, lignes_nft(t) == [] and remis(t, i) == [corps_attendu(i, "done", "verdict lisible")],
           f"illisibles non retirées : la ligne lisible n'est pas lue : {lignes_nft(t)!r} {remis(t, i)!r}")
    exiger(f, reg == lignes, f"illisibles non retirées : registre {reg!r}")
    return f


def s_ajout_au_registre_refuse(script):
    """L'AJOUT d'une ligne `commencee` refusé (fichier non inscriptible, utilisateur non privilégié) : exécutée quand
    même, protection absente avouée, registre inchangé."""
    if os.geteuid() == 0:
        refuser_de_conclure("sous root, un fichier en lecture seule reste inscriptible : l'ajout refusé ne se joue pas")
    i, ip = 1362, "203.0.113.182"
    with tempfile.TemporaryDirectory() as etat:
        autre = faite(7100, "203.0.113.100", "autre")
        poser_registre(etat, [autre], mode=0o400)
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=400)
        reg = lire_registre(etat)
    f = []
    dit(f, t, j_protection_absente(i, cause_ecriture(chemin_registre(etat))), "ajout refusé")
    exiger(f, reg == [autre] and lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"ajout refusé : {reg!r} {lignes_nft(t)!r}")
    return f


def s_registre_illisible(script):
    """Registre illisible — pas un fichier ordinaire (dit au début du tour), ou lecture refusée (utilisateur non
    privilégié) : la riposte est exécutée quand même, la protection absente avouée."""
    i, ip = 1363, "203.0.113.183"
    f = []
    with tempfile.TemporaryDirectory() as etat:
        os.makedirs(chemin_registre(etat))
        t = tour_n(script, etat, [ban(i, ip, 600)])
    dit(f, t, j_registre_non_ordinaire(chemin_registre(etat)), "pas un fichier ordinaire")
    dit(f, t, j_protection_absente(i, cause_illisible(chemin_registre(etat))), "pas un fichier ordinaire, protection")
    exiger(f, lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"pas un fichier ordinaire : {lignes_nft(t)!r}")
    if os.geteuid() == 0:
        refuser_de_conclure("sous root, un fichier de mode 000 reste lisible : la lecture refusée ne se joue pas")
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(i, ip, "x")], mode=0o000)
        t = tour_n(script, etat, [ban(i, ip, 600)])
        os.chmod(chemin_registre(etat), 0o600)
    dit(f, t, j_protection_absente(i, cause_illisible(chemin_registre(etat))), "lecture refusée, protection")
    exiger(f, lignes_nft(t) == ENSURE + [nft_pose(ip, 600)], f"lecture refusée : {lignes_nft(t)!r}")
    return f


def identite_de(pid):
    with open(f"/proc/{pid}/stat") as h:
        return f"{pid} {h.read().rsplit(') ', 1)[1].split()[19]}"


def attendre_le_fichier(chemin, s=30):
    for _ in range(s * 10):
        if os.path.exists(chemin):
            return True
        time.sleep(0.1)
    return False


def jouer_deux_executions(script, etat, lecteurs):
    """A tient le verrou, bloquée dans sa pose ; B joue pendant ce temps ; puis A est libérée."""
    vu = {}
    liberer = os.path.join(etat, "liberer")

    def pendant(pr, env):
        vu["arrivee"] = attendre_le_fichier(liberer + ".arrive")
        vu["pid"] = pr.pid
        vu["repertoire"] = os.path.exists(os.path.join(rep_etat(etat), "verrou.d"))
        vu["fichier"] = os.path.exists(os.path.join(rep_etat(etat), "verrou"))
        p = os.path.join(rep_etat(etat), "verrou.d", "porteur")
        vu["porteur"] = open(p).read().strip() if os.path.exists(p) else None
        vu["identite"] = identite_de(pr.pid) if os.path.exists(f"/proc/{pr.pid}/stat") else None
        vu["b"] = tour_n(script, etat, [ban(1372, "203.0.113.192", 600)], lecteurs=lecteurs)
        open(liberer, "w").close()

    a = tour_n(script, etat, [ban(1371, "203.0.113.191", 600)], lecteurs=lecteurs, fond=pendant,
               env_plus={"NFT_ATTENDRE_SUR": "create element*", "NFT_ATTENDRE": liberer})
    return a, vu


def juger_la_seconde_execution(f, b, ligne, quoi):
    exiger(f, b is not None and b.rc == 0 and b.accepts == [] and b.nb_verdicts == 0 and lignes_nft(b) == [],
           f"{quoi} : la seconde exécution a traité quelque chose : rc={getattr(b, 'rc', None)} "
           f"accepts={getattr(b, 'accepts', None)} nft={lignes_nft(b) if b else None}")
    if b is not None:
        dit(f, b, ligne, quoi)


def s_deux_executions_simultanees_repertoire(script):
    """Repli `mkdir` (pas de `flock`) : pendant qu'une exécution tient le verrou, une seconde sort en code 0 SANS
    RIEN TRAITER (ni liste, ni remise, ni nft) et le dit ; le porteur inscrit est le processus qui tient le verrou."""
    with tempfile.TemporaryDirectory() as etat:
        a, vu = jouer_deux_executions(script, etat, ("python3",))
        rendu = not os.path.exists(os.path.join(rep_etat(etat), "verrou.d"))
    f = []
    exiger(f, vu.get("arrivee"), "instrument : la première exécution n'a jamais atteint sa pose")
    juger_la_seconde_execution(f, vu.get("b"), f"{VERROU_DEJA_PRIS} ({os.path.join(rep_etat(etat), 'verrou.d')})", "mkdir")
    exiger(f, vu.get("identite") is not None and vu.get("porteur") == vu.get("identite"),
           f"porteur inscrit {vu.get('porteur')!r}, processus qui tient le verrou {vu.get('identite')!r}")
    verdict_est(f, a, 1371, "done")
    exiger(f, rendu, "le verrou n'est pas rendu à la fin du tour")
    return f


def s_deux_executions_simultanees_flock(script):
    """`flock` présent : il tient le verrou (le répertoire du repli n'est pas créé) ; une seconde exécution sort en
    code 0 sans rien traiter et le dit."""
    if not shutil.which("flock"):
        refuser_de_conclure("`flock` introuvable sur cette machine : la voie flock du verrou ne se joue pas")
    with tempfile.TemporaryDirectory() as etat:
        a, vu = jouer_deux_executions(script, etat, ("python3", "flock"))
    f = []
    exiger(f, vu.get("arrivee"), "instrument : la première exécution n'a jamais atteint sa pose")
    exiger(f, vu.get("fichier") and not vu.get("repertoire"), f"flock : fichier de verrou={vu.get('fichier')} répertoire du repli={vu.get('repertoire')}")
    juger_la_seconde_execution(f, vu.get("b"), f"{VERROU_DEJA_PRIS} ({os.path.join(rep_etat(etat), 'verrou')})", "flock")
    verdict_est(f, a, 1371, "done")
    return f


def poser_porteur(etat, contenu):
    os.makedirs(os.path.join(rep_etat(etat), "verrou.d"), mode=0o700)
    if contenu is not None:
        with open(os.path.join(rep_etat(etat), "verrou.d", "porteur"), "w") as h:
            h.write(contenu)


def s_verrou_orphelin_repris(script):
    """Repli `mkdir` : un verrou dont le porteur est mort (pid sans instant), dont le pid est recyclé (instant
    différent), ou jamais écrit, est ORPHELIN : repris, dit, le tour traite sa riposte, et le verrou est rendu."""
    if not os.path.exists("/proc/self/stat"):
        refuser_de_conclure("/proc absent : l'identité du porteur ne se lit pas")
    p = subprocess.Popen([shutil.which("true")])
    p.wait()
    f = []
    for nom, contenu, porteur in (("mort", f"{p.pid} -\n", f"pid {p.pid}"),
                                  ("recycle", f"{os.getpid()} 1\n", f"pid {os.getpid()}"),
                                  ("jamais ecrit", "", "jamais ecrit")):
        with tempfile.TemporaryDirectory() as etat:
            poser_porteur(etat, contenu)
            t = tour_n(script, etat, [ban(1373, "203.0.113.193", 600)])
            rendu = not os.path.exists(os.path.join(rep_etat(etat), "verrou.d"))
        dit(f, t, j_verrou_orphelin(os.path.join(rep_etat(etat), "verrou.d"), porteur), f"verrou {nom}")
        verdict_est(f, t, 1373, "done")
        exiger(f, rendu, f"verrou {nom} : non rendu à la fin du tour")
    return f


def s_verrou_vivant_respecte(script):
    """Repli `mkdir` : un porteur VIVANT (pid et instant de démarrage du processus de la garde) tient le verrou ; et un
    porteur écrit EN RETARD (après la création du répertoire) est relu : la seconde exécution ne traite rien."""
    if not os.path.exists("/proc/self/stat"):
        refuser_de_conclure("/proc absent : l'identité du porteur ne se lit pas")
    f = []
    moi = identite_de(os.getpid())
    with tempfile.TemporaryDirectory() as etat:
        poser_porteur(etat, moi + "\n")
        t = tour_n(script, etat, [ban(1374, "203.0.113.194", 600)])
    juger_la_seconde_execution(f, t, f"{VERROU_DEJA_PRIS} ({os.path.join(rep_etat(etat), 'verrou.d')})", "porteur vivant")
    with tempfile.TemporaryDirectory() as etat:
        poser_porteur(etat, None)
        ecrit = threading.Timer(0.3, lambda: open(os.path.join(rep_etat(etat), "verrou.d", "porteur"), "w").write(moi + "\n"))
        ecrit.start()
        t = tour_n(script, etat, [ban(1374, "203.0.113.194", 600)])
        ecrit.join()
    juger_la_seconde_execution(f, t, f"{VERROU_DEJA_PRIS} ({os.path.join(rep_etat(etat), 'verrou.d')})", "porteur écrit en retard")
    return f


def s_verrou_flock_apres_arret_brutal(script):
    """`flock` : un arrêt brutal ne laisse aucun verrou (le noyau le rend) — le tour suivant traite la riposte."""
    if not shutil.which("flock"):
        refuser_de_conclure("`flock` introuvable sur cette machine : la voie flock du verrou ne se joue pas")
    i, ip = 1375, "203.0.113.195"
    with tempfile.TemporaryDirectory() as etat:
        t1 = tour_n(script, etat, [ban(i, ip, 600)], lecteurs=("python3", "flock"), env_plus={"NFT_TUER_SUR": "create element*"})
        t2 = tour_n(script, etat, [ban(i, ip, 600)], lecteurs=("python3", "flock"), presents=[(ip, "reste:59m59s990ms")])
    f = []
    tue_net(f, t1, ENSURE + [nft_pose(ip, 600)], "flock, arrêt brutal")
    tait(f, t2, VERROU_DEJA_PRIS, "flock : le verrou survit à l'arrêt brutal")
    resultat_entier(f, t2, i, "done", f"{PHRASE_REPRISE} : {res_conserve(ip, 600, '59m59s990ms')}")
    return f


def s_verrou_non_pris(script):
    """Le verrou ne peut pas être pris — `flock` en échec (code autre que « déjà tenu »), fichier de verrou non
    inscriptible, répertoire du repli ni créé ni repris : le tour CONTINUE sans verrou, et c'est dit."""
    f = []
    faux_flock = {"flock": "#!/bin/sh\nexit 64\n"}
    with tempfile.TemporaryDirectory() as etat:
        t = tour_n(script, etat, [ban(1376, "203.0.113.196", 600)], faux=faux_flock)
    dit(f, t, j_verrou_non_pris(f"flock en echec (code 64) sur {os.path.join(rep_etat(etat), 'verrou')}"), "flock en échec")
    verdict_est(f, t, 1376, "done")
    with tempfile.TemporaryDirectory() as etat:
        os.makedirs(os.path.join(rep_etat(etat), "verrou"))
        t = tour_n(script, etat, [ban(1376, "203.0.113.196", 600)], faux={"flock": "#!/bin/sh\nexit 0\n"})
    dit(f, t, j_verrou_non_pris(f"{os.path.join(rep_etat(etat), 'verrou')} non inscriptible"), "fichier de verrou")
    verdict_est(f, t, 1376, "done")
    if os.geteuid() == 0:
        refuser_de_conclure("sous root, un répertoire de mode 500 se vide quand même : le repli bloqué ne se joue pas")
    with tempfile.TemporaryDirectory() as etat:
        poser_porteur(etat, "")
        bloque = os.path.join(rep_etat(etat), "verrou.d", "bloque")
        os.makedirs(bloque)
        open(os.path.join(bloque, "f"), "w").close()
        os.chmod(bloque, 0o500)
        try:
            t = tour_n(script, etat, [ban(1376, "203.0.113.196", 600)])
        finally:
            os.chmod(bloque, 0o700)
    dit(f, t, j_verrou_non_pris(f"{os.path.join(rep_etat(etat), 'verrou.d')} ni cree ni repris"), "repli bloqué")
    verdict_est(f, t, 1376, "done")
    return f


def s_verrou_orphelin_tenu_apres_reprise(script):
    """Repli `mkdir` : un verrou orphelin dit « repris » est TENU ensuite — pendant la pose, le porteur inscrit est le
    processus du tour, et aucune ligne ne dit le verrou non pris. Retirer l'orphelin sans recréer le verrou ferait
    tourner le tour sans verrou sous une phrase qui dit le contraire."""
    if not os.path.exists("/proc/self/stat"):
        refuser_de_conclure("/proc absent : l'identité du porteur ne se lit pas")
    p = subprocess.Popen([shutil.which("true")])
    p.wait()
    vu = {}
    with tempfile.TemporaryDirectory() as etat:
        poser_porteur(etat, f"{p.pid} -\n")
        liberer = os.path.join(etat, "liberer")

        def pendant(pr, env):
            vu["arrivee"] = attendre_le_fichier(liberer + ".arrive")
            q = os.path.join(rep_etat(etat), "verrou.d", "porteur")
            vu["porteur"] = open(q).read().strip() if os.path.exists(q) else None
            vu["identite"] = identite_de(pr.pid) if os.path.exists(f"/proc/{pr.pid}/stat") else None
            open(liberer, "w").close()

        t = tour_n(script, etat, [ban(1377, "203.0.113.197", 600)], fond=pendant,
                   env_plus={"NFT_ATTENDRE_SUR": "create element*", "NFT_ATTENDRE": liberer})
    f = []
    exiger(f, vu.get("arrivee"), "instrument : la pose n'a jamais été atteinte")
    dit(f, t, j_verrou_orphelin(os.path.join(rep_etat(etat), "verrou.d"), f"pid {p.pid}"), "orphelin repris")
    exiger(f, vu.get("identite") is not None and vu.get("porteur") == vu.get("identite"),
           f"verrou dit repris mais non tenu pendant la pose : porteur={vu.get('porteur')!r}, tour={vu.get('identite')!r}")
    tait(f, t, "respond: VERROU NON PRIS", "verrou dit repris puis non pris")
    verdict_est(f, t, 1377, "done")
    return f


def s_seconde_execution_ne_rejoue_rien(script):
    """Une seconde exécution pendant que la première tient le verrou ne REJOUE rien : un verdict posé dans la file de
    rejeu pendant que la première tourne n'est pas remis par la seconde, et reste en file (`flock` et repli `mkdir`).
    Prendre le verrou après le rejeu ferait remettre la file en parallèle de la première."""
    f = []
    for voie, lecteurs in (("mkdir", ("python3",)), ("flock", ("python3", "flock"))):
        if voie == "flock" and not shutil.which("flock"):
            refuser_de_conclure("`flock` introuvable sur cette machine : la voie flock du verrou ne se joue pas")
        vu = {}
        with tempfile.TemporaryDirectory() as etat:
            liberer = os.path.join(etat, "liberer")
            file_ = os.path.join(rep_etat(etat), "verdicts-a-remettre")

            def pendant(pr, env):
                vu["arrivee"] = attendre_le_fichier(liberer + ".arrive")
                with open(file_, "a") as h:
                    h.write('2999\t0\t{"id":2999,"status":"done","result":"retenu"}\n')
                vu["b"] = tour_n(script, etat, [], lecteurs=lecteurs)
                vu["file"] = open(file_).read()
                open(liberer, "w").close()

            a = tour_n(script, etat, [ban(1378, "203.0.113.198", 600)], lecteurs=lecteurs, fond=pendant,
                       env_plus={"NFT_ATTENDRE_SUR": "create element*", "NFT_ATTENDRE": liberer})
        b = vu.get("b")
        exiger(f, vu.get("arrivee"), f"{voie} : instrument, la première exécution n'a jamais atteint sa pose")
        exiger(f, b is not None and b.nb_verdicts == 0 and b.corps_remis == [],
               f"{voie} : la seconde exécution a rejoué : {getattr(b, 'corps_remis', None)!r}")
        exiger(f, "2999\t0\t" in (vu.get("file") or ""), f"{voie} : file de rejeu vidée par la seconde : {vu.get('file')!r}")
        verdict_est(f, a, 1378, "done")
    return f


def s_reprise_d_un_ban_refusee_apres_une_levee_vaine(script):
    """Même tour : une levée nft seule qui ne retire rien (`failed`, LEVEE NON FAITE), puis la REPRISE d'un ban dont
    la pose est refusée : le ban reste `failed`. Le constat « absente » ne vaut que pour une levée — sans juger le
    genre, l'état laissé par la levée précédente ferait passer le ban repris refusé pour `done`."""
    i0, ip0, i, ip = 1379, "198.51.100.179", 1380, "203.0.113.180"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [commencee(i, ip)])
        t = tour_n(script, etat, [unban(i0, ip0), ban(i, ip, 600)],
                   retraits=[("blocklist", ip0, "absent"), ("blocklist_ttl", ip0, "absent")],
                   env_plus={"NFT_CREATE_REFUS": ip}, statut=400)
        reg = lire_registre(etat) or []
    f = []
    verdict_est(f, t, i0, "failed", LEVEE_NON_FAITE.strip(" ;"))
    verdict_est(f, t, i, "failed", PHRASE_REPRISE)
    exiger(f, not any(PHRASE_ABSENTE_APRES_INTERRUPTION in c for c in remis(t, i)),
           f"ban repris dit « absente » : {remis(t, i)!r}")
    exiger(f, [l.split("\t")[4] for l in reg if l.startswith(f"{i}\tfaite\t")] == ["failed"],
           f"registre du ban repris : {reg!r}")
    return f


def s_rejeu_refuse_garde_l_entree(script):
    """Verdict retenu (503), puis son REJEU refusé définitivement (400) : l'entrée `faite` reste au registre ; re-servie
    ensuite, la riposte n'appelle plus nft et son verdict enregistré est re-remis à l'octet."""
    i, ip = 1381, "203.0.113.171"
    with tempfile.TemporaryDirectory() as etat:
        tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
        t2 = tour_n(script, etat, [], statut=400)
        reg2 = lire_registre(etat)
        t3 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")], statut=400)
    f = []
    corps = corps_attendu(i, "done", res_pose(ip, 600))
    exiger(f, remis(t2, i) == [corps], f"instrument : le rejeu n'a pas eu lieu : {remis(t2, i)!r}")
    exiger(f, reg2 == [faite(i, ip, res_pose(ip, 600))], f"rejeu refusé : l'entrée doit rester : {reg2!r}")
    exiger(f, lignes_nft(t3) == [], f"rejeu refusé : riposte REEXECUTEE ensuite : {lignes_nft(t3)!r}")
    exiger(f, remis(t3, i) == [corps], f"rejeu refusé : verdict re-remis {remis(t3, i)!r}")
    return f


def s_identifiant_prefixe_d_un_autre(script):
    """Bord de l'identifiant (la tabulation qui le termine) : le registre porte 13 et 130. (a) 13 re-servie et prise :
    seule l'entrée 13 part, 130 reste. (b) seule 130 est inscrite, 13 est servie pour la même cible : 13 est
    EXÉCUTÉE et son propre verdict remis — la ligne de 130 n'est pas lue pour 13."""
    f = []
    ip13, ip130 = "203.0.113.13", "203.0.113.130"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(13, ip13, "verdict 13"), faite(130, ip130, "verdict 130")])
        t = tour_n(script, etat, [ban(13, ip13, 600)])
        reg = lire_registre(etat)
    exiger(f, lignes_nft(t) == [] and remis(t, 13) == [corps_attendu(13, "done", "verdict 13")],
           f"(a) 13 : {lignes_nft(t)!r} {remis(t, 13)!r}")
    exiger(f, reg == [faite(130, ip130, "verdict 130")], f"(a) registre après retrait de 13 : {reg!r}")
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(130, ip13, "verdict de 130")])
        t = tour_n(script, etat, [ban(13, ip13, 600)], statut=400)
    exiger(f, lignes_nft(t) == ENSURE + [nft_pose(ip13, 600)], f"(b) 13 non exécutée : {lignes_nft(t)!r}")
    exiger(f, remis(t, 13) == [corps_attendu(13, "done", res_pose(ip13, 600))], f"(b) verdict remis pour 13 : {remis(t, 13)!r}")
    return f


def mode_du_registre(etat):
    try:
        return oct(os.stat(chemin_registre(etat)).st_mode & 0o777)
    except OSError as e:
        return f"illisible ({e})"


def s_registre_reserve_au_proprietaire(script):
    """Le registre est en mode 0600 après chaque écriture : (a) après l'AJOUT de la ligne `commencee` sur un registre
    trouvé en 0644 (le tour arrêté brutalement pendant la pose, rien d'autre n'a écrit) ; (b) après sa republication
    (issue enregistrée à la reprise)."""
    i, ip = 1382, "203.0.113.172"
    f = []
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [faite(9001, "203.0.113.101", "autre")], mode=0o644)
        t1 = tour_n(script, etat, [ban(i, ip, 600)], env_plus={"NFT_TUER_SUR": "create element*"})
        m1, reg1 = mode_du_registre(etat), lire_registre(etat)
        t2 = tour_n(script, etat, [ban(i, ip, 600)], presents=[(ip, "reste:59m59s990ms")], statut=400)
        m2, reg2 = mode_du_registre(etat), lire_registre(etat) or []
    tue_net(f, t1, ENSURE + [nft_pose(ip, 600)], "mode, arrêt pendant la pose")
    exiger(f, reg1 == [faite(9001, "203.0.113.101", "autre"), commencee(i, ip)], f"instrument (a) : registre {reg1!r}")
    exiger(f, m1 == "0o600", f"(a) registre en mode {m1} après l'ajout, attendu 0o600")
    verdict_est(f, t2, i, "done", PHRASE_REPRISE)
    exiger(f, any(l.startswith(f"{i}\tfaite\t") for l in reg2), f"instrument (b) : registre {reg2!r}")
    exiger(f, m2 == "0o600", f"(b) registre en mode {m2} après sa republication, attendu 0o600")
    return f


def s_aveu_ignore_une_ligne_illisible_non_retiree(script):
    """L'aveu d'un verdict non retenu lit la forme comme la lecture du registre : une ligne ILLISIBLE `faite` de l'id
    (statut inconnu), restée faute de pouvoir réécrire le registre, ne fait pas promettre « PAS réexécutée » — la
    lecture l'ignore, la riposte est encore `commencee` et sera REPRISE si elle est re-servie."""
    if not os.path.exists("/dev/full"):
        refuser_de_conclure("/dev/full absent : l'écriture refusée du rejeu ne peut pas être jouée")
    i, ip = 1383, "203.0.113.173"
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, [commencee(i, ip), f"{i}\tfaite\tban_ip\t{ip}\tinconnu\tverdict illisible"])
        os.makedirs(chemin_registre(etat) + ".nouveau")
        rejeu = os.path.join(rep_etat(etat), "verdicts-a-remettre")
        os.symlink("/dev/full", rejeu)
        t = tour_n(script, etat, [ban(i, ip, 600)], statut=503, faux=SOMMEIL_INSTANTANE)
    f = []
    dit(f, t, j_illisibles_non_retirees(1, chemin_registre(etat)), "instrument : ligne illisible non retirée")
    verdict_est(f, t, i, "done", PHRASE_REPRISE)
    dit(f, t, f"respond: #{i} verdict NON RETENU pour rejeu : ecriture refusee dans {rejeu} — le central re-servira "
              f"la riposte, et {CONSEQUENCE_REEXECUTEE}", "aveu")
    return f


def s_sortie_sur_mktemp_refuse_rend_le_verrou(script):
    """Repli `mkdir` : le verrou pris, la sortie 3 sur un fichier temporaire refusé (avant que la file ne soit lue) le
    REND — le répertoire du repli n'existe plus après le tour, qui n'a rien exécuté ni dit le verrou non pris."""
    i, ip = 1390, "203.0.113.184"
    with tempfile.TemporaryDirectory() as etat:
        t = tour_n(script, etat, [ban(i, ip, 600)], env_plus={"TMPDIR": "/nonexistent-plume-guard"})
        reste = os.path.exists(os.path.join(rep_etat(etat), "verrou.d"))
    f = []
    exiger(f, t.rc == 3 and "fichier temporaire refuse" in t.stderr,
           f"instrument : la sortie sur mktemp refusé n'a pas eu lieu : rc={t.rc} {t.stderr[-300:]!r}")
    tait(f, t, "respond: VERROU NON PRIS", "instrument : le verrou n'a pas été pris")
    exiger(f, lignes_nft(t) == [] and t.nb_verdicts == 0, f"mktemp refusé : action traitée {lignes_nft(t)!r}")
    exiger(f, not reste, "la sortie 3 sur mktemp refusé laisse le verrou du repli (verrou.d) derrière elle")
    return f


def s_verrou_tenu_laisse_le_registre_intact(script):
    """Une exécution qui sort au verrou (porteur vivant) ne touche pas au registre : la ligne illisible qu'elle y trouve
    reste à l'octet, et rien n'est dit écarté — l'assainissement se joue sous le verrou, par le tour qui le tient."""
    if not os.path.exists("/proc/self/stat"):
        refuser_de_conclure("/proc absent : l'identité du porteur ne se lit pas")
    lignes = ["pas une ligne du registre", faite(7030, "203.0.113.185", "ok 7030")]
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, lignes)
        with open(chemin_registre(etat), "rb") as h:
            avant = h.read()
        poser_porteur(etat, identite_de(os.getpid()) + "\n")
        t = tour_n(script, etat, [ban(1391, "203.0.113.186", 600)])
        with open(chemin_registre(etat), "rb") as h:
            apres = h.read()
    f = []
    juger_la_seconde_execution(f, t, f"{VERROU_DEJA_PRIS} ({os.path.join(rep_etat(etat), 'verrou.d')})", "verrou tenu")
    exiger(f, apres == avant, f"registre récrit par une exécution sortie au verrou : {avant!r} -> {apres!r}")
    tait(f, t, "respond: registre d execution :", "une exécution sortie au verrou dit avoir assaini le registre")
    return f


def s_ligne_a_champ_en_trop_illisible(script):
    """La forme du registre est ancrée en FIN de ligne : une `commencee` ou une `faite` suivie d'un champ de trop est
    illisible — écartée, dite (compte exact), et la riposte re-servie dont la ligne `commencee` portait ce champ de trop
    est exécutée comme neuve, sans la phrase de reprise."""
    i, ip = 1392, "203.0.113.187"
    garde = [faite(7031, "203.0.113.188", "ok 7031")]
    lignes = [commencee(i, ip) + "\tchamp-de-trop", garde[0], faite(7032, "203.0.113.189", "ok 7032") + "\tchamp-de-trop"]
    with tempfile.TemporaryDirectory() as etat:
        poser_registre(etat, lignes)
        t = tour_n(script, etat, [ban(i, ip, 600)])
        reg = lire_registre(etat)
    f = []
    dit(f, t, j_illisibles(2, chemin_registre(etat)), "lignes à champ de trop")
    resultat_entier(f, t, i, "done", res_pose(ip, 600))
    exiger(f, reg == garde, f"registre après le tour (verdict pris, entrée retirée) : {reg!r}")
    return f


SCENARIOS = {
    "json_served_python3": lambda s: s_json_servi(s, "python3"),
    "json_served_jq": lambda s: s_json_servi(s, "jq"),
    "no_reader_tsv_fallback_said": s_sans_lecteur_repli_dit,
    "older_central_tsv_despite_accept": s_central_anterieur_tsv,
    "content_type_case_insensitive": s_type_casse_libre,
    "pending_503_tsv_body_never_parsed": lambda s: s_statut_non_200(s, (), "text/plain", "201\tban_ip\t203.0.113.51\t0\n"),
    "pending_503_json_body_never_parsed": lambda s: s_statut_non_200(
        s, ("python3",), TYPE_JSON, json.dumps(ban(202, "203.0.113.52", 60)) + "\n"),
    "central_unreachable_exit_classified": s_central_injoignable,
    "illegible_line_skipped_and_said_python3": lambda s: s_ligne_illisible(s, "python3"),
    "illegible_line_skipped_and_said_jq": lambda s: s_ligne_illisible(s, "jq"),
    "out_of_contract_ttl_failed_python3": lambda s: s_duree_hors_contrat(s, "python3"),
    "out_of_contract_ttl_failed_jq": lambda s: s_duree_hors_contrat(s, "jq"),
    "nft_ttl_set_beside_the_permanent_one": s_nft_set_a_duree,
    "nft_illegible_fallback_never_permanent": s_nft_repli_illisible,
    "fail2ban_says_duration_not_carried": s_fail2ban_duree_non_portee,
    "dry_run_shows_effective_duration": s_simulation,
    "served_values_never_evaluated_python3": lambda s: s_valeurs_servies_jamais_evaluees(s, "python3"),
    "served_values_never_evaluated_jq": lambda s: s_valeurs_servies_jamais_evaluees(s, "jq"),
    "nft_unban_clears_the_ttl_set": s_nft_unban_set_a_duree,
    "nft_fresh_host_table_created": s_nft_hote_neuf,
    "nft_zero_fallback_never_permanent": s_nft_repli_nul,
    "queue_200_truncated_never_parsed_tsv": lambda s: s_200_tronque(s, None),
    "queue_200_truncated_never_parsed_python3": lambda s: s_200_tronque(s, "python3"),
    "queue_200_oversized_never_parsed": s_200_trop_gros,
    "python_reader_isolated": s_python_isole,
    "out_of_contract_line_not_reposted_while_pending": s_f_en_attente,
    "failing_reader_executes_nothing_jq": lambda s: s_lecteur_en_echec(s, "jq"),
    "failing_reader_executes_nothing_python3": lambda s: s_lecteur_en_echec(s, "python3"),
    "mktemp_refused_exit_classified": s_mktemp_refuse,
    "unasked_json_without_reader_exit_classified": s_json_non_demande_sans_lecteur,
    "tsv_last_line_without_newline_served": s_tsv_sans_fin_de_ligne,
    "big_id_refused_jq": lambda s: s_grand_id(s, "jq"),
    "big_id_refused_python3": lambda s: s_grand_id(s, "python3"),
    "negative_zero_id_is_zero_jq": lambda s: s_id_moins_zero(s, "jq"),
    "negative_zero_id_is_zero_python3": lambda s: s_id_moins_zero(s, "python3"),
    "nft_fallback_unanchored_duration_refused": s_nft_repli_sans_ancre,
    "multiline_fallback_duration_refused_whole": s_repli_multiligne,
    "crowdsec_fallback_duration_validated": s_crowdsec_repli_invalide,
    "nft_shorter_ban_keeps_the_longer_one": s_nft_ban_court_conserve_le_long,
    "nft_longer_ban_extends_in_one_transaction": s_nft_ban_long_allonge_en_une_transaction,
    "nft_absent_address_single_exclusive_pose": s_nft_absente_pose_simple,
    "nft_unreadable_remainder_rewrites_nothing": s_nft_reste_illisible_rien_recrit,
    "nft_without_awk_rewrites_nothing": s_nft_sans_awk_rien_recrit,
    "nft_every_expires_form_judged_at_its_edge": s_nft_chaque_forme_d_expires,
    "nft_expired_before_read_poses_again_once": s_nft_expire_avant_la_lecture,
    "nft_expired_before_transaction_poses_again_once": s_nft_expire_avant_la_transaction,
    "nft_refused_transaction_said": s_nft_transaction_refusee_dite,
    "nft_dry_run_promises_only_a_lengthening": s_nft_simulation_ne_promet_pas,
    "repeated_or_disordered_duration_refused_with_cause": s_duree_desordonnee_refusee,
    "cscli_keeps_its_own_duration_rule": s_cscli_garde_sa_regle_de_duree,
    "nft_exclusive_pose_refused_otherwise_said": s_nft_pose_exclusive_refusee_autrement,
    "measured_duration_forms_still_admitted": s_duree_mesuree_admise,
    "nft_endless_element_kept_with_its_own_phrase": s_nft_element_sans_fin_conserve,
    "nft_dry_run_refuses_a_repeated_unit_with_its_cause": s_nft_simulation_refuse_l_unite_repetee,
    "crowdsec_plan_names_the_command_cscli_plays": s_plan_cscli_nomme_la_commande_jouee,
    "nft_errors_read_under_a_translated_locale": s_nft_locale_traduite,
    "nft_unban_refused_on_the_permanent_set_is_failed": s_levee_refusee_sur_le_set_permanent,
    "nft_unban_refused_on_the_ttl_set_is_failed": s_levee_refusee_sur_le_set_a_duree,
    "nft_unban_refused_on_both_sets_is_failed": s_levee_refusee_sur_les_deux_sets,
    "nft_unban_absent_and_removed_is_done": s_levee_absente_et_retiree,
    "nft_unban_nothing_removed_nft_alone_is_failed": s_levee_deux_absences_nft_seul,
    "nft_unban_killed_by_a_signal_is_a_refusal": s_levee_nft_tue_par_un_signal,
    "nft_unban_refused_with_fail2ban_is_failed": s_levee_refusee_avec_fail2ban,
    "nft_unban_nothing_removed_with_fail2ban_or_crowdsec_is_done": s_levee_deux_absences_avec_fail2ban_ou_crowdsec,
    "nft_unban_exit_code_edges": s_levee_bord_des_codes,
    "nft_unban_absence_on_stdout_is_a_refusal": s_levee_absence_sur_la_sortie_standard,
    "nft_unban_read_under_a_translated_locale": s_levee_sous_une_locale_traduite,
    "nft_unban_long_refusal_bounded_per_set": s_levee_refus_bavard_borne,
    "nft_unban_no_table_or_no_ttl_set_unchanged": s_levee_sans_table_ni_set,
    "nft_unban_refused_probe_lets_the_removal_decide": s_levee_sonde_refusee,
    "nft_unban_probe_absence_read_under_a_translated_locale": s_levee_sonde_absente_sous_une_locale_traduite,
    "nft_unban_without_nft_unchanged": s_levee_sans_nft,
    "nft_unban_silent_removal_failure_is_a_refusal": s_levee_retrait_muet,
    "nft_unban_silent_probe_failure_lets_the_removal_decide": s_levee_sonde_muette,
    "nft_unban_probe_killed_or_unstarted_lets_the_removal_decide": s_levee_sonde_tuee_ou_qui_ne_part_pas,
    "nft_unban_probe_absence_on_stdout_lets_the_removal_decide": s_levee_sonde_absence_sur_la_sortie_standard,
    "nft_unban_refusal_does_not_carry_to_the_next_unban": s_levee_refus_ne_colle_pas_a_la_levee_suivante,
    "nft_unban_removal_does_not_carry_to_the_next_unban": s_levee_retrait_ne_colle_pas_a_la_levee_suivante,
    "nft_unban_unit_separator_in_a_refusal_becomes_a_space": s_levee_refus_au_separateur_d_unite,
    # `P10.21-n` — une riposte re-servie n'est jamais exécutée une seconde fois à l'aveugle.
    "reserved_ban_stopped_before_its_verdict_is_not_reexecuted": s_arret_avant_la_remise_ban,
    "reserved_unban_stopped_before_its_verdict_is_not_reexecuted": s_arret_avant_la_remise_levee,
    "reserved_unban_interrupted_is_resumed_and_said": s_arret_pendant_la_levee,
    "reserved_ban_interrupted_is_resumed_and_said": s_arret_pendant_la_pose,
    "resumed_unban_refusal_stays_failed": s_levee_refusee_a_la_reprise,
    "unwritable_state_executes_and_says_no_protection": s_etat_non_inscriptible,
    "full_replay_queue_reserved_riposte_not_reexecuted": s_file_de_rejeu_pleine,
    "refused_replay_write_reserved_riposte_not_reexecuted": s_ecriture_du_rejeu_refusee,
    "definitive_refusal_reserved_riposte_not_reexecuted": s_refus_definitif_du_central,
    "abandoned_replay_reserved_riposte_not_reexecuted": s_rejeu_abandonne,
    "execution_register_bound_at_each_edge": s_registre_borne,
    "execution_register_never_evicts_a_started_riposte": s_registre_commencees_jamais_evincees,
    "execution_register_illegible_lines_dropped_and_said": s_registre_lignes_illisibles,
    "dry_run_and_refusals_write_nothing_to_the_register": s_simulacre_et_refus_n_ecrivent_rien,
    "register_entry_removed_on_2xx_and_ok_false_kept_on_503": s_registre_retire_ou_garde,
    "reused_id_for_another_riposte_is_executed": s_identifiant_reutilise,
    "recorded_verdict_re_remitted_as_is_before_any_precheck": s_verdict_enregistre_avant_tout_controle,
    "register_line_bounded_target_and_result": s_ligne_du_registre_bornee,
    "register_zero_filled_tail_still_read": s_queue_de_zeros_lue,
    "reused_id_avowal_reads_the_last_line": s_aveu_lit_la_derniere_ligne,
    "overlong_id_executed_without_protection_said": s_identifiant_trop_long,
    "refused_register_rewrites_said_and_harmless": s_ecritures_du_registre_refusees,
    "refused_register_append_executes_and_says": s_ajout_au_registre_refuse,
    "illegible_register_executes_and_says": s_registre_illisible,
    "concurrent_runs_mkdir_lock_one_processes": s_deux_executions_simultanees_repertoire,
    "concurrent_runs_flock_one_processes": s_deux_executions_simultanees_flock,
    "orphan_mkdir_lock_taken_back": s_verrou_orphelin_repris,
    "live_mkdir_lock_respected": s_verrou_vivant_respecte,
    "flock_lock_does_not_survive_a_brutal_stop": s_verrou_flock_apres_arret_brutal,
    "lock_not_taken_run_continues_and_says": s_verrou_non_pris,
    "orphan_mkdir_lock_held_after_its_takeover": s_verrou_orphelin_tenu_apres_reprise,
    "second_run_replays_nothing_while_the_lock_is_held": s_seconde_execution_ne_rejoue_rien,
    "resumed_ban_refused_after_a_vain_unban_stays_failed": s_reprise_d_un_ban_refusee_apres_une_levee_vaine,
    "refused_replay_keeps_the_register_entry": s_rejeu_refuse_garde_l_entree,
    "register_id_never_matches_an_id_it_prefixes": s_identifiant_prefixe_d_un_autre,
    "register_kept_owner_only_after_each_write": s_registre_reserve_au_proprietaire,
    "avowal_ignores_an_illegible_line_left_in_the_register": s_aveu_ignore_une_ligne_illisible_non_retiree,
    "mktemp_refused_exit_gives_back_the_mkdir_lock": s_sortie_sur_mktemp_refuse_rend_le_verrou,
    "held_lock_leaves_the_register_untouched": s_verrou_tenu_laisse_le_registre_intact,
    "register_line_with_a_trailing_field_is_illegible": s_ligne_a_champ_en_trop_illisible,
}

# (nom, motif exact dans respond.sh, remplacement, scénarios qui DOIVENT rougir)
MUTANTS = [
    ("accept_header_never_sent", 'lire_la_file "$_file_corps" -H "Accept: $TYPE_FILE_JSON"', 'lire_la_file "$_file_corps"',
     ["json_served_python3", "json_served_jq"]),
    ("accept_header_sent_without_reader", 'if [ -n "$LECTEUR_JSON" ]; then\n  if _file_w', 'if :; then\n  if _file_w',
     ["no_reader_tsv_fallback_said"]),
    ("served_ttl_ignored", 'EFF_DUR="${_ta_duree}s"', 'EFF_DUR="$DUR"', ["json_served_python3", "dry_run_shows_effective_duration"]),
    ("jq_not_preferred_reader", "if command -v jq >/dev/null 2>&1; then LECTEUR_JSON=jq", "if false; then LECTEUR_JSON=jq",
     ["json_served_jq"]),
    ("fallback_cause_not_said", 'DUR_PROV="PLUME_BAN_DURATION de l hote, duree NON servie : $DUREE_NON_SERVIE"', 'DUR_PROV=""',
     ["no_reader_tsv_fallback_said", "older_central_tsv_despite_accept"]),
    ("content_type_not_judged", 'if [ "$_file_type_nu" = "$TYPE_FILE_JSON" ]; then', 'if [ -n "$LECTEUR_JSON" ]; then',
     ["older_central_tsv_despite_accept"]),
    ("content_type_case_sensitive", "printf '%s' \"$_file_type\" | tr 'A-Z' 'a-z' |", "printf '%s' \"$_file_type\" |",
     ["content_type_case_insensitive"]),
    ("http_status_not_judged", 'if [ "$_file_rc" != 0 ] || [ "$_file_code" != 200 ]; then', 'if [ "$_file_rc" != 0 ]; then',
     ["pending_503_tsv_body_never_parsed", "pending_503_json_body_never_parsed"]),
    ("unreadable_queue_exits_silent", "ce n est pas une file vide : $(reponse_bornee \"$_file_lu\")\" >&2\n  exit 3",
     "ce n est pas une file vide : $(reponse_bornee \"$_file_lu\")\" >&2\n  exit 0",
     ["pending_503_tsv_body_never_parsed", "central_unreachable_exit_classified"]),
    ("illegible_line_silenced", 'X) echo "respond: file JSON : ligne $_n ILLISIBLE', 'X) : "respond: file JSON : ligne $_n ILLISIBLE',
     ["illegible_line_skipped_and_said_python3", "illegible_line_skipped_and_said_jq"]),
    ("python_reader_dies_on_bad_line", "    except Exception:\n        return \"X\\tjson_illisible\"", "    except KeyError:\n        return \"X\\tjson_illisible\"",
     ["illegible_line_skipped_and_said_python3"]),
    ("jq_ttl_upper_bound_dropped", "$o.ban_ttl_s < 1 or $o.ban_ttl_s > 31536000", "$o.ban_ttl_s < 1",
     ["out_of_contract_ttl_failed_jq"]),
    ("python_ttl_lower_bound_dropped", 'o["ban_ttl_s"] < 1 or o["ban_ttl_s"] > BORNE_DUREE', 'o["ban_ttl_s"] > BORNE_DUREE',
     ["out_of_contract_ttl_failed_python3"]),
    ("python_null_ttl_accepted", '    elif o["ban_ttl_s"] is None:\n        duree = "!nulle"\n', "",
     ["out_of_contract_ttl_failed_python3"]),
    ("out_of_contract_ttl_applied_with_host_duration",
     '      !*)\n        post_result "$id" failed "duree du ban servie HORS CONTRAT',
     '      !*) EFF_DUR="$DUR" ;;\n      !!*)\n        post_result "$id" failed "duree du ban servie HORS CONTRAT',
     ["out_of_contract_ttl_failed_python3", "out_of_contract_ttl_failed_jq"]),
    ("nft_ttl_set_not_created_on_existing_table", '  nft list set inet plume "$NFT_SET_TTL" >/dev/null 2>&1 && return 0',
     "  return 0", ["nft_ttl_set_beside_the_permanent_one"]),
    ("nft_ban_without_timeout", 'nft create element inet plume "$NFT_SET_TTL" "{ $_np_ip timeout $_np_dur }"',
     'nft create element inet plume blocklist "{ $_np_ip }"', ["nft_ttl_set_beside_the_permanent_one"]),
    ("nft_illegible_duration_not_refused",
     '      duree_de_ban_lisible "$EFF_DUR" nft || { OUT="duree $EFF_DUR illisible ou nulle comme timeout nft, rien pose (cause : $DUREE_CAUSE)"; return 1; }\n', "",
     ["nft_illegible_fallback_never_permanent"]),
    ("fail2ban_silent_on_duration", "[duree %s (%s) NON portee par fail2ban : le ban dure le bantime de la jail %s]", "[%.0s%.0s%.0s]",
     ["fail2ban_says_duration_not_carried"]),
    ("dry_run_plan_uses_host_duration", "printf 'cscli decisions add -i %s -d %s -t ban -R plume-playbook [duree %s : %s]' \"$2\" \"$EFF_DUR\"",
     "printf 'cscli decisions add -i %s -d %s -t ban -R plume-playbook [duree %s : %s]' \"$2\" \"$DUR\"",
     ["dry_run_shows_effective_duration"]),
    ("served_target_not_checked_as_ip", '  if ! is_ip "$target"; then post_result "$id" failed "cible non-IP: $target"; return 0; fi\n', "",
     ["served_values_never_evaluated_python3", "served_values_never_evaluated_jq"]),
    ("python_reader_accepts_any_target", '    if not isinstance(t, str) or t == "" or hors_ascii(t):', "    if False:",
     ["served_values_never_evaluated_python3"]),
    ("python_reader_accepts_any_id", "    if not entier(i) or i < 0 or i > BORNE_ID:", "    if False:",
     ["served_values_never_evaluated_python3"]),
    ("jq_reader_accepts_any_id",
     'elif ((($o.id | entier) and $o.id >= 0 and $o.id <= 9007199254740991) | not) then "X\\tid_illisible"',
     'elif false then "X\\tid_illisible"', ["served_values_never_evaluated_jq"]),
    ("jq_reader_accepts_any_kind",
     'if ($o.kind | type) != "string" or $o.kind == "" or ($o.kind | hors_ascii) then', "if false then",
     ["served_values_never_evaluated_jq"]),
    ("jq_reader_accepts_any_target",
     'elif ($o.target | type) != "string" or $o.target == "" or ($o.target | hors_ascii) then', "elif false then",
     ["served_values_never_evaluated_jq"]),
    ("jq_reader_accepts_any_dry_run", 'elif ($o.dry_run | type) != "boolean" then', "elif false then",
     ["served_values_never_evaluated_jq"]),
    ("python_reader_not_isolated", 'python3) python3 -I -c "$PY_FILE_JSON"', 'python3) python3 -c "$PY_FILE_JSON"',
     ["python_reader_isolated"]),
    ("nft_unban_leaves_the_ttl_set",
     '    if [ "$NFT_SONDE" != absent ]; then\n      nft_classer_le_retrait blocklist_ttl "$1"; OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"\n',
     '    if false; then\n      nft_classer_le_retrait blocklist_ttl "$1"; OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"\n',
     ["nft_unban_clears_the_ttl_set"]),
    ("nft_fresh_host_table_skipped", "  if ! nft list table inet plume >/dev/null 2>&1; then\n    nft add table",
     "  if false; then\n    nft add table", ["nft_fresh_host_table_created"]),
    ("nft_zero_duration_accepted", "  printf '%s' \"$1\" | grep -q '[1-9]' || { DUREE_CAUSE=\"nulle\"; return 1; }", "  :",
     ["nft_zero_fallback_never_permanent"]),
    ("queue_curl_failure_not_judged", 'if [ "$_file_rc" != 0 ] || [ "$_file_code" != 200 ]; then',
     'if [ "$_file_code" != 200 ]; then',
     ["queue_200_truncated_never_parsed_tsv", "queue_200_truncated_never_parsed_python3"]),
    ("queue_body_unbounded", '--max-filesize "$FILE_OCTETS_MAX" "$@"', '"$@"', ["queue_200_oversized_never_parsed"]),
    ("out_of_contract_line_reposted_while_pending", '        if verdict_en_attente_de_remise "$_r_2"; then\n',
     "        if false; then\n", ["out_of_contract_line_not_reposted_while_pending"]),
    ('nft_fallback_regex_unanchored', "grep -qE '^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$'",
     "grep -qE '([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?'", ['repeated_or_disordered_duration_refused_with_cause']),
    # `P11.25-a` : la forme générale (`<n>` + unité, répétée) est jugée AVANT la règle d'ordre propre à nft ; `4hd` ne
    # doit partir ni à nft ni à cscli. Sans ancrage, cscli la recevait (la règle d'ordre ne vaut que pour nft).
    ('duration_regex_unanchored', "grep -qE '^([0-9]+[dhms])+$'", "grep -qE '([0-9]+[dhms])+'",
     ['crowdsec_fallback_duration_validated']),
    ('jq_id_upper_bound_dropped', ' and $o.id <= 9007199254740991) | not)', ') | not)',
     ['big_id_refused_jq']),
    ('python_id_upper_bound_dropped', '    if not entier(i) or i < 0 or i > BORNE_ID:', '    if not entier(i) or i < 0:',
     ['big_id_refused_python3']),
    ('jq_reader_failure_ignored', '    jq)      jq -R -r "$JQ_FILE_JSON" < "$1" > "$2" ;;', '    jq)      jq -R -r "$JQ_FILE_JSON" < "$1" > "$2" || : ;;',
     ['failing_reader_executes_nothing_jq']),
    ('python_reader_failure_ignored', '    python3) python3 -I -c "$PY_FILE_JSON" < "$1" > "$2" ;;', '    python3) python3 -I -c "$PY_FILE_JSON" < "$1" > "$2" || : ;;',
     ['failing_reader_executes_nothing_python3']),
    ('reader_failure_continues', 'en ECHEC : AUCUNE action executee ce tour-ci" >&2\n    exit 3', 'en ECHEC : AUCUNE action executee ce tour-ci" >&2\n    :',
     ['failing_reader_executes_nothing_jq', 'failing_reader_executes_nothing_python3']),
    ('unasked_json_exits_silent', 'aucun lecteur JSON sur cet hote : AUCUNE action executee" >&2\n    exit 3', 'aucun lecteur JSON sur cet hote : AUCUNE action executee" >&2\n    exit 0',
     ['unasked_json_without_reader_exit_classified']),
    ('mktemp_refusal_exits_silent', 'aucune action recuperee ni executee" >&2; exit 3; }\n_file_enreg', 'aucune action recuperee ni executee" >&2; exit 0; }\n_file_enreg',
     ['mktemp_refused_exit_classified']),
    ('tsv_last_line_dropped', 'while IFS=\'\t\' read -r id kind target dry <&7 || [ -n "${id:-}" ]; do', "while IFS='\t' read -r id kind target dry <&7; do",
     ['tsv_last_line_without_newline_served']),
    ('jq_negative_zero_id_kept', '    else (($o.id | floor) + 0 | tostring) as $id\n', '    else ($o.id | floor | tostring) as $id\n',
     ['negative_zero_id_is_zero_jq']),
    ('fallback_duration_judged_line_by_line', '  case "$1" in \'\'|*[!0-9dhms]*) DUREE_CAUSE="illisible (attendu <n>s, m, h ou d)"; return 1 ;; esac\n', '',
     ['multiline_fallback_duration_refused_whole']),
    ('crowdsec_fallback_duration_not_validated', '      duree_de_ban_lisible "$EFF_DUR" cscli || { OUT="duree $EFF_DUR illisible ou nulle pour cscli, rien pose (cause : $DUREE_CAUSE)"; return 1; }\n', '',
     ['crowdsec_fallback_duration_validated']),
    ('crowdsec_dry_run_plan_not_validated', '      if duree_de_ban_lisible "$EFF_DUR" cscli; then\n        printf \'cscli decisions add', "      if :; then\n        printf 'cscli decisions add",
     ['crowdsec_fallback_duration_validated']),
    # `P11.25-a` — un ban plus court ne raccourcit jamais un ban en cours.
    ("remainder_comparison_inverted", 'if (r >= d) print "conserver " reste; else print "allonger " reste',
     'if (r < d) print "conserver " reste; else print "allonger " reste',
     ["nft_shorter_ban_keeps_the_longer_one", "nft_longer_ban_extends_in_one_transaction",
      "nft_every_expires_form_judged_at_its_edge"]),
    ("remainder_equal_to_request_rewritten", 'if (r >= d) print "conserver " reste', 'if (r > d) print "conserver " reste',
     ["nft_every_expires_form_judged_at_its_edge"]),
    ("lengthening_not_atomic",
     """if _np_tx=$(printf 'delete element inet plume %s { %s }\\nadd element inet plume %s { %s timeout %s }\\n' \\\n            "$NFT_SET_TTL" "$_np_ip" "$NFT_SET_TTL" "$_np_ip" "$_np_dur" | LC_ALL=C nft -f - 2>&1); then""",
     """if _np_tx=$(LC_ALL=C nft delete element inet plume "$NFT_SET_TTL" "{ $_np_ip }" 2>&1 && LC_ALL=C nft add element inet plume "$NFT_SET_TTL" "{ $_np_ip timeout $_np_dur }" 2>&1); then""",
     ["nft_longer_ban_extends_in_one_transaction"]),
    ("unreadable_remainder_treated_as_absent",
     '      *)\n        OUT="$PHRASE_DUREE_NON_APPLIQUEE : son reste',
     '      *)\n        OUT=$(LC_ALL=C nft add element inet plume "$NFT_SET_TTL" "{ $_np_ip timeout $_np_dur }" 2>&1); return 0 ;;\n      __jamais__)\n        OUT="$PHRASE_DUREE_NON_APPLIQUEE : son reste',
     ["nft_unreadable_remainder_rewrites_nothing", "nft_without_awk_rewrites_nothing"]),
    ("failed_read_taken_for_an_absence", "        *'No such file or directory'*)\n          if [ \"$_np_reprise\" = 0 ]",
     "        *)\n          if [ \"$_np_reprise\" = 0 ]", ["nft_unreadable_remainder_rewrites_nothing"]),
    ("kept_ban_said_as_a_bare_done",
     'OUT="$PHRASE_BAN_CONSERVE (reste ${_np_verdict#conserver } >= $_np_dur demandes), rien n est recrit"; return 0 ;;',
     'OUT=""; return 0 ;;', ["nft_shorter_ban_keeps_the_longer_one"]),
    ("unreadable_remainder_said_as_done",
     'OUT="$PHRASE_DUREE_NON_APPLIQUEE : son reste n a pas pu etre lu (cause=${_np_verdict#illisible }), rien n est recrit$_np_detail"\n        return 1 ;;',
     'OUT=""\n        return 0 ;;', ["nft_unreadable_remainder_rewrites_nothing"]),
    ("duration_gate_relaxed", "  if [ \"$2\" = nft ] && ! printf '%s' \"$1\" | grep -qE '^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$'; then",
     "  if false; then", ["repeated_or_disordered_duration_refused_with_cause"]),
    ("disorder_cause_not_said", '    DUREE_CAUSE="unite repetee ou desordonnee (', '    DUREE_CAUSE="illisible (',
     ["repeated_or_disordered_duration_refused_with_cause"]),
    ("disorder_gate_applied_to_cscli", "  if [ \"$2\" = nft ] && ! printf '%s' \"$1\" | grep -qE", "  if ! printf '%s' \"$1\" | grep -qE",
     ["cscli_keeps_its_own_duration_rule"]),
    ("exclusive_pose_refused_otherwise_said_done", '*) OUT="$_np_sortie"; return 1 ;; esac', '*) OUT="$_np_sortie"; return 0 ;; esac',
     ["nft_exclusive_pose_refused_otherwise_said"]),
    ("retry_counter_shared_by_the_tour", "_np_ip=$1; _np_dur=$2; _np_reprise=0", "_np_ip=$1; _np_dur=$2; : ${_np_reprise:=0}",
     ["nft_expired_before_read_poses_again_once"]),
    ("plan_names_the_replacing_add", "printf 'nft create element inet plume %s { %s timeout %s } [duree",
     "printf 'nft add element inet plume %s { %s timeout %s } [duree",
     ["nft_dry_run_promises_only_a_lengthening", "nft_absent_address_single_exclusive_pose"]),
    ("zero_cause_emptied", 'DUREE_CAUSE="nulle"; return 1;', 'DUREE_CAUSE=""; return 1;',
     ["nft_zero_fallback_never_permanent"]),
    ("nft_dry_run_cause_dropped",
     "illisible ou nulle comme timeout nft (cause : %s) — aucun ban permanent pose a la place' \"$EFF_DUR\" \"$DUR_PROV\" \"$DUREE_CAUSE\"",
     "illisible ou nulle comme timeout nft (cause : %.0s) — aucun ban permanent pose a la place' \"$EFF_DUR\" \"$DUR_PROV\" \"$DUREE_CAUSE\"",
     ["nft_zero_fallback_never_permanent"]),
    ("crowdsec_dry_run_cause_dropped",
     "illisible ou nulle (cause : %s) — aucun ban pose' \"$EFF_DUR\" \"$DUR_PROV\" \"$DUREE_CAUSE\"",
     "illisible ou nulle (cause : %.0s) — aucun ban pose' \"$EFF_DUR\" \"$DUR_PROV\" \"$DUREE_CAUSE\"",
     ["crowdsec_fallback_duration_validated"]),
    ("crowdsec_enforce_cause_dropped", 'pour cscli, rien pose (cause : $DUREE_CAUSE)"', 'pour cscli, rien pose"',
     ["crowdsec_fallback_duration_validated"]),
    ("nft_enforce_cause_dropped", 'comme timeout nft, rien pose (cause : $DUREE_CAUSE)"', 'comme timeout nft, rien pose"',
     ["nft_zero_fallback_never_permanent"]),
    ("pose_not_exclusive", 'LC_ALL=C nft create element inet plume "$NFT_SET_TTL"', 'LC_ALL=C nft add element inet plume "$NFT_SET_TTL"',
     ["nft_shorter_ban_keeps_the_longer_one", "nft_absent_address_single_exclusive_pose"]),
    ("retry_before_read_dropped", 'then _np_reprise=1; continue; fi   # expire avant la lecture', 'then :; fi   # expire avant la lecture',
     ["nft_expired_before_read_poses_again_once"]),
    ("retry_before_transaction_dropped", 'then _np_reprise=1; continue; fi ;;   # expire avant la transaction',
     'then :; fi ;;   # expire avant la transaction', ["nft_expired_before_transaction_poses_again_once"]),
    ("retry_unbounded", '_np_verdict="illisible element_disparu_apres_la_reprise" ;;', 'continue ;;',
     ["nft_unreadable_remainder_rewrites_nothing"]),
    ("days_factor_wrong", 'if (u == "d") { r = 1; f = 86400000 }', 'if (u == "d") { r = 1; f = 3600000 }',
     ["nft_every_expires_form_judged_at_its_edge"]),
    ("milliseconds_read_as_minutes", 'if (substr(s, 1, 2) == "ms") { u = "ms"; s = substr(s, 3) } else', 'if (0) { } else',
     ["nft_every_expires_form_judged_at_its_edge"]),
    ("expires_unit_order_not_judged", "        if (r <= prec) return -1\n", "",
     ["nft_unreadable_remainder_rewrites_nothing"]),
    ("expires_absence_not_judged", '      if (nexp != 1) { print "illisible expires_absent"; exit }\n', "",
     ["nft_unreadable_remainder_rewrites_nothing"]),
    ("duplicate_address_not_judged", '      if (trouve > 1) { print "illisible adresse_en_double"; exit }\n', "",
     ["nft_unreadable_remainder_rewrites_nothing"]),
    ("awk_failure_not_judged", '|| _np_verdict="illisible lecteur_en_echec"', '|| :',
     ["nft_without_awk_rewrites_nothing"]),
    ("refused_transaction_retried", "        case \"$_np_tx\" in\n          *'No such file or directory'*)", "        case \"$_np_tx\" in\n          *)",
     ["nft_refused_transaction_said"]),
    ("nft_dry_run_promises_the_requested_duration",
     " ; deja banni : duree appliquee seulement si elle allonge, jamais raccourci'", "'",
     ["nft_dry_run_promises_only_a_lengthening"]),
    ("nft_gate_repeated_minutes_admitted", "([0-9]+m)?([0-9]+s)?$'", "([0-9]+m)*([0-9]+s)?$'",
     ["repeated_or_disordered_duration_refused_with_cause"]),
    ("nft_plan_judged_with_the_cscli_rule", '      if duree_de_ban_lisible "$EFF_DUR" nft; then',
     '      if duree_de_ban_lisible "$EFF_DUR" cscli; then', ["nft_dry_run_refuses_a_repeated_unit_with_its_cause"]),
    ("cscli_plan_judged_with_the_nft_rule", '      if duree_de_ban_lisible "$EFF_DUR" cscli; then',
     '      if duree_de_ban_lisible "$EFF_DUR" nft; then', ["crowdsec_plan_names_the_command_cscli_plays"]),
    ("endless_element_read_as_unreadable", '      if (nattr == 0) { print "conserver_sans_fin"; exit }\n', "",
     ["nft_endless_element_kept_with_its_own_phrase"]),
    ("endless_judged_without_its_attributes", '      if (nattr == 0) { print "conserver_sans_fin"; exit }',
     '      if (nexp == 0) { print "conserver_sans_fin"; exit }', ["nft_unreadable_remainder_rewrites_nothing"]),
    ("timeout_attribute_not_counted",
     '          if (g == "timeout" || g == "timeout," || g == "expires" || g == "expires,") nattr++\n',
     '          if (g == "expires" || g == "expires,") nattr++\n', ["nft_unreadable_remainder_rewrites_nothing"]),
    ("endless_said_as_a_finite_remainder", 'OUT="$PHRASE_BAN_CONSERVE_SANS_FIN (', 'OUT="$PHRASE_BAN_CONSERVE (',
     ["nft_endless_element_kept_with_its_own_phrase"]),
    ("endless_kept_said_failed", '$_np_dur demandes), rien n est recrit"; return 0 ;;\n      "allonger "*)',
     '$_np_dur demandes), rien n est recrit"; return 1 ;;\n      "allonger "*)', ["nft_endless_element_kept_with_its_own_phrase"]),
    ("read_without_lc_all", 'if _np_lu=$(LC_ALL=C nft get element', 'if _np_lu=$(nft get element',
     ["nft_errors_read_under_a_translated_locale"]),
    # `P11.25-a` — la levée nft suit la règle du démon : chaque retrait classé, un refus rend `failed`.
    ('unban_permanent_set_or_true_restored',
     '    nft_classer_le_retrait blocklist "$1"; OUT="$OUT [nft]$NFT_RETRAIT_TEXTE"',
     '    NFT_RETRAIT_TEXTE=$(nft delete element inet plume blocklist "{ $1 }" 2>&1 || true); NFT_RETRAIT=retiree; OUT="$OUT [nft]$NFT_RETRAIT_TEXTE"',
     ['nft_unban_refused_on_the_permanent_set_is_failed', 'nft_unban_refused_on_both_sets_is_failed', 'nft_unban_refused_with_fail2ban_is_failed']),
    ('unban_ttl_set_or_true_restored',
     '      nft_classer_le_retrait blocklist_ttl "$1"; OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"',
     '      NFT_RETRAIT_TEXTE=$(nft delete element inet plume blocklist_ttl "{ $1 }" 2>&1 || true); NFT_RETRAIT=retiree; OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"',
     ['nft_unban_refused_on_the_ttl_set_is_failed', 'nft_unban_refused_on_both_sets_is_failed', 'nft_unban_killed_by_a_signal_is_a_refusal']),
    ('unban_absence_taken_for_a_refusal',
     '    *"$NFT_MESSAGE_D_ABSENCE"*) if [ "$_cr_code" -lt 126 ]; then return 0; fi ;;',
     '    *"$NFT_MESSAGE_D_ABSENCE"*) ;;',
     ['nft_unban_absent_and_removed_is_done', 'nft_unban_nothing_removed_with_fail2ban_or_crowdsec_is_done', 'nft_unban_read_under_a_translated_locale', 'nft_unban_exit_code_edges']),
    ('unban_refusal_taken_for_an_absence',
     '  NFT_RETRAIT=refus\n',
     '  NFT_RETRAIT=absente\n',
     ['nft_unban_refused_on_the_permanent_set_is_failed', 'nft_unban_refused_on_the_ttl_set_is_failed', 'nft_unban_refused_with_fail2ban_is_failed']),
    ('unban_permanent_set_never_classified',
     'OUT="$OUT [nft]$NFT_RETRAIT_TEXTE"\n    case "$NFT_RETRAIT" in refus) _ua_refus=1 ;; retiree) _ua_retrait=1 ;; esac\n',
     'OUT="$OUT [nft]$NFT_RETRAIT_TEXTE"\n',
     ['nft_unban_refused_on_the_permanent_set_is_failed', 'nft_unban_absent_and_removed_is_done', 'nft_unban_refused_with_fail2ban_is_failed']),
    ('unban_ttl_set_never_classified',
     'OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"\n      case "$NFT_RETRAIT" in refus) _ua_refus=1 ;; retiree) _ua_retrait=1 ;; esac\n',
     'OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"\n',
     ['nft_unban_refused_on_the_ttl_set_is_failed', 'nft_unban_killed_by_a_signal_is_a_refusal', 'nft_unban_absent_and_removed_is_done']),
    ('unban_signal_read_as_an_absence',
     'if [ "$_cr_code" -lt 126 ]; then return 0',
     'if :; then return 0',
     ['nft_unban_killed_by_a_signal_is_a_refusal', 'nft_unban_exit_code_edges']),
    ('unban_unstarted_command_read_as_an_absence',
     'if [ "$_cr_code" -lt 126 ]; then return 0',
     'if [ "$_cr_code" -lt 128 ]; then return 0',
     ['nft_unban_exit_code_edges']),
    ('unban_code_125_read_as_a_refusal',
     'if [ "$_cr_code" -lt 126 ]; then return 0',
     'if [ "$_cr_code" -lt 125 ]; then return 0',
     ['nft_unban_exit_code_edges']),
    ('unban_signal_not_said',
     '  if [ "$_cr_code" -gt 128 ]; then _cr_cause="$_cr_cause, nft interrompu par le signal $((_cr_code - 128))"; fi\n',
     '',
     ['nft_unban_killed_by_a_signal_is_a_refusal', 'nft_unban_exit_code_edges']),
    ('unban_code_128_said_as_a_signal',
     'if [ "$_cr_code" -gt 128 ]; then _cr_cause=',
     'if [ "$_cr_code" -ge 128 ]; then _cr_cause=',
     ['nft_unban_exit_code_edges']),
    ('unban_code_129_not_said_as_a_signal',
     'if [ "$_cr_code" -gt 128 ]; then _cr_cause=',
     'if [ "$_cr_code" -gt 129 ]; then _cr_cause=',
     ['nft_unban_exit_code_edges']),
    ('unban_absence_read_on_stdout',
     '"{ $2 }" 3>&2 2>&1 1>&3 3>&-)',
     '"{ $2 }" 2>&1)',
     ['nft_unban_absence_on_stdout_is_a_refusal']),
    ('unban_stdout_hidden_from_the_journal',
     '"{ $2 }" 3>&2 2>&1 1>&3 3>&-)',
     '"{ $2 }" 2>&1 1>/dev/null)',
     ['nft_unban_absence_on_stdout_is_a_refusal']),
    ('unban_removal_without_lc_all',
     'LC_ALL=C LANG=C nft delete element',
     'LANG=C nft delete element',
     ['nft_unban_read_under_a_translated_locale']),
    ('unban_refusal_verdict_dropped',
     '  if [ "$_ua_refus" = 1 ]; then return 1; fi\n',
     '',
     ['nft_unban_refused_on_the_permanent_set_is_failed', 'nft_unban_refused_on_the_ttl_set_is_failed', 'nft_unban_killed_by_a_signal_is_a_refusal']),
    ('unban_refusal_hidden_by_another_backend',
     '  if [ "$_ua_refus" = 1 ]; then return 1; fi',
     '  if [ "$_ua_refus" = 1 ] && [ "$_ua_autres" = 0 ]; then return 1; fi',
     ['nft_unban_refused_with_fail2ban_is_failed']),
    ('unban_nothing_removed_said_done',
     '    OUT="$OUT ; LEVEE NON FAITE : adresse absente de chaque set nft tente, rien n a ete retire"; return 1\n',
     '    return 0\n',
     ['nft_unban_nothing_removed_nft_alone_is_failed']),
    ('unban_nothing_removed_failed_despite_other_backends',
     '[ "$_ua_retrait" = 0 ] && [ "$_ua_autres" = 0 ]; then',
     '[ "$_ua_retrait" = 0 ]; then',
     ['nft_unban_nothing_removed_with_fail2ban_or_crowdsec_is_done']),
    ('unban_fail2ban_not_counted_as_another_backend',
     'then _ua_autres=1; OUT="$OUT [f2b]',
     'then OUT="$OUT [f2b]',
     ['nft_unban_nothing_removed_with_fail2ban_or_crowdsec_is_done']),
    ('unban_crowdsec_not_counted_as_another_backend',
     'then _ua_autres=1; OUT="$OUT [cs]',
     'then OUT="$OUT [cs]',
     ['nft_unban_nothing_removed_with_fail2ban_or_crowdsec_is_done']),
    ('unban_refusal_text_without_its_set',
     'NFT_RETRAIT_TEXTE="REFUS du retrait dans $1 $NFT_REFUS_TEXTE"',
     'NFT_RETRAIT_TEXTE="REFUS du retrait $NFT_REFUS_TEXTE"',
     ['nft_unban_refused_on_the_permanent_set_is_failed', 'nft_unban_refused_on_the_ttl_set_is_failed']),
    ('unban_refusal_text_without_what_nft_wrote',
     'NFT_REFUS_TEXTE="($_cr_cause) : $_cr_coupe"',
     'NFT_REFUS_TEXTE="($_cr_cause)"',
     ['nft_unban_refused_on_the_permanent_set_is_failed', 'nft_unban_refused_on_the_ttl_set_is_failed']),
    ('unban_refusal_text_unbounded',
     '| coupe_sur_caractere "$NFT_PART_DE_RETRAIT_OCTETS")',
     '| cat)',
     ['nft_unban_long_refusal_bounded_per_set']),
    ('unban_refusal_cut_mid_character',
     '| coupe_sur_caractere "$NFT_PART_DE_RETRAIT_OCTETS")',
     '| LC_ALL=C cut -b "1-$NFT_PART_DE_RETRAIT_OCTETS")',
     ['nft_unban_long_refusal_bounded_per_set']),
    ('unban_refusal_cut_not_said',
     'then _cr_coupe="$_cr_coupe [...]"; fi',
     'then :; fi',
     ['nft_unban_long_refusal_bounded_per_set']),
    ('unban_refusal_kept_on_several_lines',
     '_cr_entier=$(printf \'%s\' "$2" | tr \'\\000-\\037\' \' \')',
     '_cr_entier=$2',
     ['nft_unban_long_refusal_bounded_per_set']),
    ('unban_refusal_other_control_characters_kept',
     'tr \'\\000-\\037\' \' \')\n  _cr_coupe=',
     'tr \'\\n\' \' \')\n  _cr_coupe=',
     ['nft_unban_long_refusal_bounded_per_set']),
    # `P11.25-a` — une sonde refusée n'est pas une absence : le retrait est tenté et son classement tranche.
    ('unban_refused_probe_read_as_an_absence',
     '  NFT_SONDE=refus\n',
     '  NFT_SONDE=absent\n',
     ['nft_unban_refused_probe_lets_the_removal_decide']),
    ('unban_refused_table_probe_skips_the_removals',
     '  if [ "$NFT_SONDE" != absent ]; then\n    nft_classer_le_retrait blocklist "$1"',
     '  if [ "$NFT_SONDE" = present ]; then\n    nft_classer_le_retrait blocklist "$1"',
     ['nft_unban_refused_probe_lets_the_removal_decide']),
    ('unban_refused_ttl_probe_skips_the_removal',
     '    if [ "$NFT_SONDE" != absent ]; then\n      nft_classer_le_retrait blocklist_ttl',
     '    if [ "$NFT_SONDE" = present ]; then\n      nft_classer_le_retrait blocklist_ttl',
     ['nft_unban_refused_probe_lets_the_removal_decide']),
    ('unban_refused_probe_not_said',
     '  echo "respond: SONDE nft REFUSEE sur $_so_objet $NFT_REFUS_TEXTE ; le retrait est tente, son classement tranche" >&2\n',
     '',
     ['nft_unban_refused_probe_lets_the_removal_decide']),
    ('unban_probe_absence_read_as_a_refusal',
     '  if nft_lire_l_echec "$_so_retour" "$_so_ecrit"; then NFT_SONDE=absent; return 0; fi\n',
     '',
     ['nft_unban_no_table_or_no_ttl_set_unchanged', 'nft_unban_nothing_removed_nft_alone_is_failed',
      'nft_unban_probe_absence_read_under_a_translated_locale']),
    ('unban_probe_without_lc_all',
     'LC_ALL=C LANG=C nft list "$@"',
     'nft list "$@"',
     ['nft_unban_probe_absence_read_under_a_translated_locale']),
    ('unban_nft_presence_not_checked',
     'if command -v nft >/dev/null 2>&1; then nft_sonder',
     'if :; then nft_sonder',
     ['nft_unban_without_nft_unchanged']),
    ('unban_part_bound_raised',
     'NFT_PART_DE_RETRAIT_OCTETS=120',
     'NFT_PART_DE_RETRAIT_OCTETS=240',
     ['nft_unban_long_refusal_bounded_per_set']),
    # `P11.25-a` — échec muet, code et sortie standard de la sonde, verdict remis à zéro à chaque levée, borne haute de la
    # plage des caractères de contrôle.
    ('unban_silent_removal_read_as_an_absence',
     'if nft_lire_l_echec "$_cr_retour" "$NFT_RETRAIT_TEXTE"; then NFT_RETRAIT=absente',
     'if [ -z "$NFT_RETRAIT_TEXTE" ] || nft_lire_l_echec "$_cr_retour" "$NFT_RETRAIT_TEXTE"; then NFT_RETRAIT=absente',
     ['nft_unban_silent_removal_failure_is_a_refusal']),
    ('unban_silent_removal_read_as_removed',
     '3>&2 2>&1 1>&3 3>&-); then\n    NFT_RETRAIT=retiree; return 0\n  else\n    _cr_retour=$?\n  fi\n',
     '3>&2 2>&1 1>&3 3>&-); then\n    NFT_RETRAIT=retiree; return 0\n  else\n    _cr_retour=$?\n  fi\n'
     '  [ -n "$NFT_RETRAIT_TEXTE" ] || { NFT_RETRAIT=retiree; return 0; }\n',
     ['nft_unban_silent_removal_failure_is_a_refusal']),
    ('unban_silent_probe_read_as_an_absence',
     'if nft_lire_l_echec "$_so_retour" "$_so_ecrit"; then NFT_SONDE=absent',
     'if [ -z "$_so_ecrit" ] || nft_lire_l_echec "$_so_retour" "$_so_ecrit"; then NFT_SONDE=absent',
     ['nft_unban_silent_probe_failure_lets_the_removal_decide']),
    ('unban_silent_failure_read_as_an_absence',
     'nft_lire_l_echec() {\n  _cr_code=$1\n',
     'nft_lire_l_echec() {\n  _cr_code=$1\n  [ -n "$2" ] || return 0\n',
     ['nft_unban_silent_removal_failure_is_a_refusal', 'nft_unban_silent_probe_failure_lets_the_removal_decide']),
    ('unban_probe_code_ignored',
     'if nft_lire_l_echec "$_so_retour" "$_so_ecrit"',
     'if nft_lire_l_echec 1 "$_so_ecrit"',
     ['nft_unban_probe_killed_or_unstarted_lets_the_removal_decide']),
    ('unban_probe_code_lost',
     'else _so_retour=$?; fi',
     'else _so_retour=1; fi',
     ['nft_unban_probe_killed_or_unstarted_lets_the_removal_decide']),
    ('unban_probe_stdout_read',
     'nft list "$@" 2>&1 >/dev/null)',
     'nft list "$@" 2>&1)',
     ['nft_unban_probe_absence_on_stdout_lets_the_removal_decide']),
    ('unban_removal_carried_to_the_next_unban',
     '_ua_refus=0; _ua_retrait=0\n',
     '_ua_refus=0; _ua_retrait=${_ua_retrait:-0}\n',
     ['nft_unban_removal_does_not_carry_to_the_next_unban']),
    ('unban_refusal_carried_to_the_next_unban',
     '_ua_autres=0; _ua_refus=0;',
     '_ua_autres=0; _ua_refus=${_ua_refus:-0};',
     ['nft_unban_refusal_does_not_carry_to_the_next_unban']),
    ('unban_refusal_unit_separator_kept',
     "_cr_entier=$(printf '%s' \"$2\" | tr '\\000-\\037' ' ')",
     "_cr_entier=$(printf '%s' \"$2\" | tr '\\000-\\036' ' ')",
     ['nft_unban_unit_separator_in_a_refusal_becomes_a_space']),
    # `P10.21-n` — registre d'exécution : une riposte re-servie n'est jamais exécutée une seconde fois à l'aveugle.
    ('reserved_faite_riposte_executed_again',
     '  if [ "$REG_ETAT" = faite ]; then\n    echo "respond: #$id NON reexecutee : deja FAITE',
     '  if false; then\n    echo "respond: #$id NON reexecutee : deja FAITE',
     ['reserved_ban_stopped_before_its_verdict_is_not_reexecuted', 'reserved_unban_stopped_before_its_verdict_is_not_reexecuted',
      'full_replay_queue_reserved_riposte_not_reexecuted', 'refused_replay_write_reserved_riposte_not_reexecuted',
      'definitive_refusal_reserved_riposte_not_reexecuted', 'abandoned_replay_reserved_riposte_not_reexecuted',
      'execution_register_illegible_lines_dropped_and_said', 'register_zero_filled_tail_still_read']),
    ('re_remission_not_said',
     '    echo "respond: #$id NON reexecutee : deja FAITE (registre d execution), verdict enregistre RE-REMIS ($REG_STATUT)" >&2\n',
     '',
     ['reserved_ban_stopped_before_its_verdict_is_not_reexecuted']),
    ('re_remission_status_forced_done',
     'post_result "$id" "$REG_STATUT" "$REG_RESULTAT"',
     'post_result "$id" done "$REG_RESULTAT"',
     ['recorded_verdict_re_remitted_as_is_before_any_precheck']),
    ('faite_check_yields_to_the_allowlist',
     '  if [ "$REG_ETAT" = faite ]; then\n',
     '  if [ "$REG_ETAT" = faite ] && [ "$(verdict_liste_epargne "$ALLOWFILE" "$ALLOW_CONFIGUREE" "$target")" != epargnee ]; then\n',
     ['recorded_verdict_re_remitted_as_is_before_any_precheck']),
    ('nothing_written_before_enforce',
     '    *) registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || _ta_protege=0 ;;',
     '    *) : ;;',
     ['reserved_unban_interrupted_is_resumed_and_said', 'reserved_ban_interrupted_is_resumed_and_said']),
    ('reused_id_not_inscribed_before_enforce',
     '      registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || _ta_protege=0 ;;\n    *)',
     '      : ;;\n    *)',
     ['reused_id_avowal_reads_the_last_line']),
    ('reused_id_not_said',
     '      echo "respond: #$id identifiant deja inscrit au registre d execution pour une AUTRE riposte',
     '      : "respond: #$id identifiant deja inscrit au registre d execution pour une AUTRE riposte',
     ['reused_id_for_another_riposte_is_executed']),
    ('resumption_not_said_in_the_result',
     '  if [ "$_ta_reprise" = 1 ]; then _ta_resultat="$PHRASE_REPRISE : $_ta_resultat"; fi\n',
     '',
     ['reserved_unban_interrupted_is_resumed_and_said', 'reserved_ban_interrupted_is_resumed_and_said',
      'resumed_unban_refusal_stays_failed']),
    ('resumption_not_said_in_the_journal',
     '      echo "respond: #$id REPRISE : une execution',
     '      : "respond: #$id REPRISE : une execution',
     ['reserved_ban_interrupted_is_resumed_and_said']),
    ('resumed_unban_found_absent_stays_failed',
     '[ "$kind" = unban_ip ] && [ "$UA_RIEN_RETIRE" = 1 ]; then',
     '[ "$kind" = unban_ip ] && [ "$UA_RIEN_RETIRE" = 9 ]; then',
     ['reserved_unban_interrupted_is_resumed_and_said']),
    ('resumed_unban_refusal_said_done',
     '[ "$kind" = unban_ip ] && [ "$UA_RIEN_RETIRE" = 1 ]; then',
     '[ "$kind" = unban_ip ]; then',
     ['resumed_unban_refusal_stays_failed']),
    ('unresumed_unban_found_absent_said_done',
     'if [ "$_ta_reprise" = 1 ] && [ "$_ta_statut" = failed ]',
     'if [ "$_ta_statut" = failed ]',
     ['nft_unban_nothing_removed_nft_alone_is_failed']),
    ('nothing_removed_flag_carried_to_the_next_unban',
     '  UA_RIEN_RETIRE=0; UA_OUT_AVANT_VERDICT=""\n  if command',
     '  UA_OUT_AVANT_VERDICT=""\n  if command',
     ['resumed_unban_refusal_stays_failed']),
    ('outcome_never_recorded',
     'if [ "$_ta_protege" = 1 ] && ! registre_marquer_faite',
     'if false && ! registre_marquer_faite',
     ['reserved_ban_stopped_before_its_verdict_is_not_reexecuted', 'definitive_refusal_reserved_riposte_not_reexecuted']),
    ('outcome_not_recorded_silently',
     '    echo "respond: #$id issue NON enregistree au registre d execution',
     '    : "respond: #$id issue NON enregistree au registre d execution',
     ['refused_register_rewrites_said_and_harmless']),
    ('register_result_keeps_its_control_characters',
     '''_mf_res=$(printf '%s' "$5" | tr '\\000-\\037' ' ' | coupe_sur_caractere''',
     '''_mf_res=$(printf '%s' "$5" | coupe_sur_caractere''',
     ['register_line_bounded_target_and_result']),
    ('register_result_cut_mid_character',
     '''| coupe_sur_caractere "$REGISTRE_RESULTAT_OCTETS")''',
     '''| LC_ALL=C cut -b "1-$REGISTRE_RESULTAT_OCTETS")''',
     ['register_line_bounded_target_and_result']),
    ('register_result_bound_raised',
     'REGISTRE_RESULTAT_OCTETS=400',
     'REGISTRE_RESULTAT_OCTETS=401',
     ['register_line_bounded_target_and_result']),
    ('register_token_unbounded',
     '''LC_ALL=C tr -c '!-~' '_' | LC_ALL=C cut -b "1-$1")''',
     '''LC_ALL=C tr -c '!-~' '_')''',
     ['register_line_bounded_target_and_result']),
    ('register_token_keeps_spaces',
     '''LC_ALL=C tr -c '!-~' '_' |''',
     '''LC_ALL=C tr -c ' -~' '_' |''',
     ['overlong_id_executed_without_protection_said']),
    ('overlong_id_bound_off_by_one',
     'if [ "${#1}" -gt "$REGISTRE_ID_CHIFFRES" ]; then',
     'if [ "${#1}" -ge "$REGISTRE_ID_CHIFFRES" ]; then',
     ['overlong_id_executed_without_protection_said']),
    ('overlong_id_bound_raised',
     'REGISTRE_ID_CHIFFRES=19',
     'REGISTRE_ID_CHIFFRES=20',
     ['overlong_id_executed_without_protection_said']),
    ('register_bound_raised',
     'REGISTRE_LIGNES=264',
     'REGISTRE_LIGNES=265',
     ['execution_register_bound_at_each_edge']),
    ('register_bound_lowered',
     'REGISTRE_LIGNES=264',
     'REGISTRE_LIGNES=263',
     ['execution_register_bound_at_each_edge']),
    ('register_eviction_starts_one_line_late',
     '[ "$_fp_n" -ge "$REGISTRE_LIGNES" ] || return 0',
     '[ "$_fp_n" -gt "$REGISTRE_LIGNES" ] || return 0',
     ['execution_register_bound_at_each_edge']),
    ('register_eviction_one_short',
     '_fp_trop=$((_fp_n - REGISTRE_LIGNES + 1))',
     '_fp_trop=$((_fp_n - REGISTRE_LIGNES))',
     ['execution_register_bound_at_each_edge']),
    ('register_eviction_takes_started_ripostes',
     'grep -n "^[0-9]*\tfaite\t"',
     'grep -n "^[0-9]*\t"',
     ['execution_register_never_evicts_a_started_riposte']),
    ('register_eviction_partial',
     'if [ "$_fp_k" -lt "$_fp_trop" ]; then',
     'if [ "$_fp_k" -lt 1 ]; then',
     ['execution_register_never_evicts_a_started_riposte']),
    ('register_eviction_silent',
     '    echo "respond: registre d execution PLEIN',
     '    : "respond: registre d execution PLEIN',
     ['execution_register_bound_at_each_edge']),
    ('unavailable_register_suspends_the_ban',
     '    *) registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || _ta_protege=0 ;;',
     '    *) registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || return 0 ;;',
     ['execution_register_never_evicts_a_started_riposte', 'unwritable_state_executes_and_says_no_protection',
      'refused_register_append_executes_and_says']),
    ('absent_protection_not_said',
     '    echo "respond: #$id protection contre la REEXECUTION ABSENTE',
     '    : "respond: #$id protection contre la REEXECUTION ABSENTE',
     ['unwritable_state_executes_and_says_no_protection', 'execution_register_never_evicts_a_started_riposte',
      'illegible_register_executes_and_says', 'overlong_id_executed_without_protection_said',
      'refused_register_append_executes_and_says']),
    ('illegible_register_read_as_absent',
     '    illisible) _ta_protege=0; REG_CAUSE="registre d execution illisible ($REGISTRE_FICHIER)" ;;',
     '    illisible) : ;;',
     ['illegible_register_executes_and_says']),
    ('register_read_error_read_as_absent',
     '  if _rl=$(registre_texte 2>/dev/null); then :; else REG_ETAT=illisible; return 0; fi',
     '  _rl=$(registre_texte 2>/dev/null) || :',
     ['illegible_register_executes_and_says']),
    ('non_regular_register_read_as_absent',
     '  [ -f "$REGISTRE_FICHIER" ] || { REG_ETAT=illisible; return 0; }',
     '  [ -f "$REGISTRE_FICHIER" ] || return 0',
     ['illegible_register_executes_and_says']),
    ('lookup_ignores_the_target',
     'if [ "$_rl_genre" != "$2" ] || [ "$_rl_cible" != "$3" ]; then',
     'if [ "$_rl_genre" != "$2" ]; then',
     ['reused_id_for_another_riposte_is_executed']),
    ('lookup_ignores_the_kind',
     'if [ "$_rl_genre" != "$2" ] || [ "$_rl_cible" != "$3" ]; then',
     'if [ "$_rl_cible" != "$3" ]; then',
     ['reused_id_for_another_riposte_is_executed']),
    ('lookup_reads_an_illegible_line',
     '''  _rl=$(printf '%s\\n' "$_rl" | LC_ALL=C grep "^$1\t" | LC_ALL=C grep -E "$REGISTRE_FORME" | sed -n '$p')''',
     '''  _rl=$(printf '%s\\n' "$_rl" | LC_ALL=C grep "^$1\t" | sed -n '$p')''',
     ['refused_register_rewrites_said_and_harmless']),
    ('lookup_reads_the_first_line',
     '''LC_ALL=C grep "^$1\t" | LC_ALL=C grep -E "$REGISTRE_FORME" | sed -n '$p')''',
     '''LC_ALL=C grep "^$1\t" | LC_ALL=C grep -E "$REGISTRE_FORME" | sed -n '1p')''',
     ['reused_id_for_another_riposte_is_executed']),
    ('zero_bytes_reach_grep',
     '''registre_texte() { tr -d '\\000' < "$REGISTRE_FICHIER"; }''',
     '''registre_texte() { cat "$REGISTRE_FICHIER"; }''',
     ['register_zero_filled_tail_still_read']),
    ('illegible_lines_not_dropped',
     'prendre_le_verrou\nregistre_assainir\n',
     'prendre_le_verrou\n',
     ['execution_register_illegible_lines_dropped_and_said']),
    ('illegible_lines_dropped_silently',
     '    echo "respond: registre d execution : $_ra_ecartees ligne(s) illisible(s) ecartee(s)',
     '    : "respond: registre d execution : $_ra_ecartees ligne(s) illisible(s) ecartee(s)',
     ['execution_register_illegible_lines_dropped_and_said']),
    ('illegible_lines_miscounted',
     '_ra_ecartees=$((_ra_total - _ra_bonnes))',
     '_ra_ecartees=$((_ra_total - _ra_bonnes - 1))',
     ['execution_register_illegible_lines_dropped_and_said']),
    ('illegible_lines_kept_silently',
     '  echo "respond: registre d execution : $_ra_ecartees ligne(s) illisible(s) dans',
     '  : "respond: registre d execution : $_ra_ecartees ligne(s) illisible(s) dans',
     ['refused_register_rewrites_said_and_harmless']),
    ('non_regular_register_not_said',
     '    echo "respond: registre d execution $REGISTRE_FICHIER illisible (pas un fichier ordinaire)',
     '    : "respond: registre d execution $REGISTRE_FICHIER illisible (pas un fichier ordinaire)',
     ['illegible_register_executes_and_says']),
    ('dry_run_writes_the_register',
     '  if [ "$APPLY" != "1" ] || [ "${dry:-1}" = "1" ]; then\n',
     '  if [ "$APPLY" != "1" ] || [ "${dry:-1}" = "1" ]; then\n    registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || :\n',
     ['dry_run_and_refusals_write_nothing_to_the_register']),
    ('protected_refusal_writes_the_register',
     'if protected "$target"; then post_result',
     'if protected "$target"; then registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || :; post_result',
     ['dry_run_and_refusals_write_nothing_to_the_register']),
    ('spared_refusal_writes_the_register',
     '    epargnee) post_result',
     '    epargnee) registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || :; post_result',
     ['dry_run_and_refusals_write_nothing_to_the_register']),
    ('out_of_contract_ttl_refusal_writes_the_register',
     '      !*)\n        post_result',
     '      !*)\n        registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || :\n        post_result',
     ['dry_run_and_refusals_write_nothing_to_the_register']),
    ('non_ip_refusal_writes_the_register',
     'if ! is_ip "$target"; then post_result',
     'if ! is_ip "$target"; then registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || :; post_result',
     ['dry_run_and_refusals_write_nothing_to_the_register']),
    ('entry_kept_after_2xx',
     '        registre_retirer "$1"\n        return 0 ;;',
     '        return 0 ;;',
     ['reserved_ban_stopped_before_its_verdict_is_not_reexecuted', 'register_entry_removed_on_2xx_and_ok_false_kept_on_503']),
    ('entry_kept_after_ok_false',
     '        registre_retirer "$1"\n        return 0 ;;',
     '''        case "$_rv_corps" in *'"ok":false'*) ;; *) registre_retirer "$1" ;; esac\n        return 0 ;;''',
     ['register_entry_removed_on_2xx_and_ok_false_kept_on_503']),
    ('entry_removed_on_503',
     '      503|502|504|000) ;;',
     '      503|502|504|000) registre_retirer "$1" ;;',
     ['register_entry_removed_on_2xx_and_ok_false_kept_on_503', 'full_replay_queue_reserved_riposte_not_reexecuted']),
    ('entry_removed_on_definitive_refusal',
     '''      *) echo "respond: #$1 verdict REFUSE par le central (HTTP $_rv_code), non reessaye : $(reponse_bornee "$_rv_corps")" >&2; return 0 ;;''',
     '''      *) echo "respond: #$1 verdict REFUSE par le central (HTTP $_rv_code), non reessaye : $(reponse_bornee "$_rv_corps")" >&2; registre_retirer "$1"; return 0 ;;''',
     ['definitive_refusal_reserved_riposte_not_reexecuted']),
    ('replay_2xx_keeps_the_entry',
     '        esac\n        registre_retirer "$_rj_id" ;;',
     '        esac ;;',
     ['register_entry_removed_on_2xx_and_ok_false_kept_on_503']),
    ('refused_entry_removal_silent',
     '  echo "respond: #$1 verdict pris par le central, mais son entree du registre d execution n est PAS retiree',
     '  : "respond: #$1 verdict pris par le central, mais son entree du registre d execution n est PAS retiree',
     ['refused_register_rewrites_said_and_harmless']),
    ('avowal_always_promises_reexecution',
     '  if [ -f "$REGISTRE_FICHIER" ] && registre_texte 2>/dev/null',
     '  if false && registre_texte 2>/dev/null',
     ['full_replay_queue_reserved_riposte_not_reexecuted', 'refused_replay_write_reserved_riposte_not_reexecuted',
      'abandoned_replay_reserved_riposte_not_reexecuted']),
    ('avowal_never_promises_reexecution',
     '  if [ -f "$REGISTRE_FICHIER" ] && registre_texte 2>/dev/null',
     '  if : || registre_texte 2>/dev/null',
     ['unwritable_state_executes_and_says_no_protection']),
    ('avowal_reads_a_superseded_faite_line',
     '''LC_ALL=C grep "^$1\t" | sed -n '$p' | LC_ALL=C grep -q "^$1\tfaite\t"''',
     '''LC_ALL=C grep -q "^$1\tfaite\t"''',
     ['reused_id_avowal_reads_the_last_line']),
    # `P10.21-n` — verrou : une seule exécution de l'agent à la fois.
    ('lock_never_taken',
     'prendre_le_verrou\nregistre_assainir\n',
     'registre_assainir\n',
     ['concurrent_runs_mkdir_lock_one_processes', 'concurrent_runs_flock_one_processes', 'live_mkdir_lock_respected']),
    ('mkdir_second_run_processes_anyway',
     '($VERROU_REPERTOIRE)" >&2; exit 0; fi',
     '($VERROU_REPERTOIRE)" >&2; return 0; fi',
     ['concurrent_runs_mkdir_lock_one_processes', 'live_mkdir_lock_respected']),
    ('mkdir_second_run_exits_non_zero',
     '($VERROU_REPERTOIRE)" >&2; exit 0; fi',
     '($VERROU_REPERTOIRE)" >&2; exit 1; fi',
     ['concurrent_runs_mkdir_lock_one_processes']),
    ('mkdir_second_run_silent',
     'if porteur_vivant "$_pl_lu"; then echo "respond: $PHRASE_VERROU_DEJA_PRIS ($VERROU_REPERTOIRE)" >&2;',
     'if porteur_vivant "$_pl_lu"; then :;',
     ['concurrent_runs_mkdir_lock_one_processes']),
    ('flock_second_run_exits_non_zero',
     '($VERROU_FICHIER)" >&2; exit 0; fi',
     '($VERROU_FICHIER)" >&2; exit 1; fi',
     ['concurrent_runs_flock_one_processes']),
    ('flock_second_run_silent',
     'if [ "$_pl_rc" = 1 ]; then echo "respond: $PHRASE_VERROU_DEJA_PRIS ($VERROU_FICHIER)" >&2;',
     'if [ "$_pl_rc" = 1 ]; then :;',
     ['concurrent_runs_flock_one_processes']),
    ('flock_not_preferred',
     '  if command -v flock >/dev/null 2>&1; then\n',
     '  if false; then\n',
     ['concurrent_runs_flock_one_processes']),
    ('flock_held_read_as_a_failure',
     'if [ "$_pl_rc" = 1 ]; then',
     'if [ "$_pl_rc" = 99 ]; then',
     ['concurrent_runs_flock_one_processes']),
    ('flock_failure_read_as_held',
     'if [ "$_pl_rc" = 1 ]; then',
     'if [ "$_pl_rc" != 0 ]; then',
     ['lock_not_taken_run_continues_and_says']),
    ('flock_failure_silent',
     '    echo "respond: VERROU NON PRIS (flock en echec',
     '    : "respond: VERROU NON PRIS (flock en echec',
     ['lock_not_taken_run_continues_and_says']),
    ('flock_file_not_tested_before_exec',
     '    if ! (umask 077 && : >> "$VERROU_FICHIER") 2>/dev/null; then\n',
     '    if false; then\n',
     ['lock_not_taken_run_continues_and_says']),
    ('flock_file_unwritable_silent',
     '      echo "respond: VERROU NON PRIS ($VERROU_FICHIER non inscriptible)',
     '      : "respond: VERROU NON PRIS ($VERROU_FICHIER non inscriptible)',
     ['lock_not_taken_run_continues_and_says']),
    ('unwritable_state_lock_silent',
     '    echo "respond: VERROU NON PRIS (etat local $REJEU_DIR non inscriptible)',
     '    : "respond: VERROU NON PRIS (etat local $REJEU_DIR non inscriptible)',
     ['unwritable_state_executes_and_says_no_protection']),
    ('holder_start_time_ignored',
     '  [ "$_pv_debut" = - ] && return 0\n',
     '  return 0\n',
     ['orphan_mkdir_lock_taken_back']),
    ('holder_liveness_not_checked',
     '  kill -0 "$_pv_pid" 2>/dev/null || return 1\n',
     '',
     ['orphan_mkdir_lock_taken_back']),
    ('holder_start_time_wrong_field',
     "| cut -d' ' -f20)",
     "| cut -d' ' -f21)",
     ['live_mkdir_lock_respected', 'concurrent_runs_mkdir_lock_one_processes']),
    ('holder_not_reread_after_the_wait',
     '    if [ -z "$_pl_lu" ]; then\n      sleep 1',
     '    if false; then\n      sleep 1',
     ['live_mkdir_lock_respected']),
    ('holder_not_written',
     '''(umask 077 && printf '%s\\n' "$_pl_moi" > "$VERROU_REPERTOIRE/porteur")''',
     '''(umask 077 && : > "$VERROU_REPERTOIRE/porteur")''',
     ['concurrent_runs_mkdir_lock_one_processes']),
    ('orphan_lock_not_said',
     '    echo "respond: verrou ORPHELIN repris',
     '    : "respond: verrou ORPHELIN repris',
     ['orphan_mkdir_lock_taken_back', 'reserved_unban_interrupted_is_resumed_and_said']),
    ('orphan_lock_not_removed',
     '    rm -rf "$VERROU_REPERTOIRE" 2>/dev/null || :\n  done',
     '    :\n  done',
     ['orphan_mkdir_lock_taken_back']),
    ('lock_fallback_failure_silent',
     '  echo "respond: VERROU NON PRIS ($VERROU_REPERTOIRE ni cree ni repris)',
     '  : "respond: VERROU NON PRIS ($VERROU_REPERTOIRE ni cree ni repris)',
     ['lock_not_taken_run_continues_and_says']),
    ('mkdir_lock_never_released',
     '  if [ "$VERROU_REPERTOIRE_PRIS" = 1 ]; then rm -rf "$VERROU_REPERTOIRE"',
     '  if false; then rm -rf "$VERROU_REPERTOIRE"',
     ['orphan_mkdir_lock_taken_back', 'concurrent_runs_mkdir_lock_one_processes']),
    ('queue_trap_drops_the_lock_release',
     '''trap 'rm -f "$_file_corps" "$_file_enreg"; rendre_le_verrou' EXIT''',
     '''trap 'rm -f "$_file_corps" "$_file_enreg"' EXIT''',
     ['orphan_mkdir_lock_taken_back', 'concurrent_runs_mkdir_lock_one_processes']),
    ('register_state_check_skipped',
     '  etat_de_rejeu_pret || { REG_CAUSE="etat local $REJEU_DIR non inscriptible"; return 1; }\n',
     '',
     ['unwritable_state_executes_and_says_no_protection']),
    # `P10.21-n` — sites relevés sans témoin par la vérification indépendante, chacun rouge sur son scénario.
    ('register_rewrite_drops_ids_sharing_a_prefix',
     'LC_ALL=C grep -v "^$1\t" || [ $? = 1 ]',
     'LC_ALL=C grep -v "^$1" || [ $? = 1 ]',
     ['register_id_never_matches_an_id_it_prefixes']),
    ('register_lookup_reads_an_id_sharing_its_prefix',
     '''  _rl=$(printf '%s\\n' "$_rl" | LC_ALL=C grep "^$1\t" |''',
     '''  _rl=$(printf '%s\\n' "$_rl" | LC_ALL=C grep "^$1" |''',
     ['register_id_never_matches_an_id_it_prefixes']),
    ('register_published_world_readable',
     'if chmod 600 "$REGISTRE_FICHIER.nouveau"',
     'if chmod 644 "$REGISTRE_FICHIER.nouveau"',
     ['register_kept_owner_only_after_each_write']),
    ('register_append_world_readable',
     '  chmod 600 "$REGISTRE_FICHIER" 2>/dev/null || :\n',
     '  chmod 644 "$REGISTRE_FICHIER" 2>/dev/null || :\n',
     ['register_kept_owner_only_after_each_write']),
    ('register_append_keeps_the_mode_found',
     '  chmod 600 "$REGISTRE_FICHIER" 2>/dev/null || :\n',
     '',
     ['register_kept_owner_only_after_each_write']),
    ('orphan_lock_removed_but_not_taken_back',
     '  for _pl_essai in 1 2; do\n',
     '  for _pl_essai in 1; do\n',
     ['orphan_mkdir_lock_held_after_its_takeover']),
    ('lock_taken_after_the_replay',
     'prendre_le_verrou\nregistre_assainir\n\n# --- le rejeu passe AVANT la liste : une liste vide ou injoignable n empeche pas de remettre ---\nrejouer_les_verdicts_retenus\n',
     'registre_assainir\n\n# --- le rejeu passe AVANT la liste : une liste vide ou injoignable n empeche pas de remettre ---\nrejouer_les_verdicts_retenus\nprendre_le_verrou\n',
     ['second_run_replays_nothing_while_the_lock_is_held']),
    ('resumed_failure_said_done_whatever_the_kind',
     '[ "$kind" = unban_ip ] && [ "$UA_RIEN_RETIRE" = 1 ]; then',
     '[ "$UA_RIEN_RETIRE" = 1 ]; then',
     ['resumed_ban_refused_after_a_vain_unban_stays_failed']),
    ('replay_refusal_removes_the_entry',
     '''abandonne : $(reponse_bornee "$_rv_corps")" >&2 ;;''',
     '''abandonne : $(reponse_bornee "$_rv_corps")" >&2; registre_retirer "$_rj_id" ;;''',
     ['refused_replay_keeps_the_register_entry']),
    ('avowal_reads_an_illegible_line',
     '''registre_texte 2>/dev/null | LC_ALL=C grep -E "$REGISTRE_FORME" | LC_ALL=C grep "^$1\t" |''',
     '''registre_texte 2>/dev/null | LC_ALL=C grep "^$1\t" |''',
     ['avowal_ignores_an_illegible_line_left_in_the_register']),
    ('mkdir_lock_release_not_trapped_when_taken',
     "      trap 'rendre_le_verrou' EXIT\n",
     "      :\n",
     ['mktemp_refused_exit_gives_back_the_mkdir_lock']),
    ('register_cleaned_before_the_lock',
     'prendre_le_verrou\nregistre_assainir\n',
     'registre_assainir\nprendre_le_verrou\n',
     ['held_lock_leaves_the_register_untouched']),
    ('register_form_without_its_final_anchor',
     "[^\\t]*)$'",
     "[^\\t]*)'",
     ['register_line_with_a_trailing_field_is_illegible']),
    # Le corps remis garde ses sauts de ligne bruts : le démon le refuse (400). Rouge sur le premier scénario par le
    # verdict qui manque, sur le second par le seul jugement de `REMISES_REFUSEES` (sans lui, ce scénario reste vert).
    ('remit_body_keeps_raw_line_breaks',
     "esc() { printf '%s' \"$1\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g' | tr '\\n\\r\\t' '   '; }",
     "esc() { printf '%s' \"$1\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g'; }",
     ['crowdsec_fallback_duration_validated', 'register_line_bounded_target_and_result']),
]


def jouer_tout(script, noms=None):
    rouges = {}
    for nom, s in SCENARIOS.items():
        if noms is not None and nom not in noms:
            continue
        REMISES_REFUSEES.clear()
        fautes = list(s(script))
        if REMISES_REFUSEES:
            fautes.append(f"le faux central a refusé {len(REMISES_REFUSEES)} remise(s), comme le démon (JSON strict, UTF-8 "
                          f"valide) : {REMISES_REFUSEES[:2]!r}")
        if fautes:
            rouges[nom] = fautes
    return rouges


def coherence_du_contrat(src):
    f = []
    exiger(f, f'TYPE_FILE_JSON="{TYPE_JSON}"' in src, f"respond.sh ne demande pas le type du démon ({TYPE_JSON})")
    for lecteur, motif in (("jq", f"$o.ban_ttl_s > {BORNE}"), ("python3", f"BORNE_DUREE = {BORNE}")):
        exiger(f, motif in src, f"la borne du lecteur {lecteur} n'est pas celle du démon ({BORNE}) : `{motif}` absent")
    return f


def selection(prefixe):
    """`--scenarios=a,b` / `--mutants=x,y` : pour itérer sur une partie. Sans l'option : None (tout)."""
    for a in sys.argv[1:]:
        if a.startswith(prefixe):
            return set(n for n in a[len(prefixe):].split(",") if n)
    return None


def main():
    src = open(SCRIPT, encoding="utf-8").read()
    erreurs = coherence_du_contrat(src) + epreuve_du_lecteur_du_faux_central()
    noms_s, noms_m = selection("--scenarios="), selection("--mutants=")
    inconnus = sorted((noms_s or set()) - set(SCENARIOS)) + sorted((noms_m or set()) - {m[0] for m in MUTANTS})
    if inconnus:
        refuser_de_conclure(f"sélection inconnue : {inconnus}")
    if noms_s is not None or noms_m is not None:
        print("::warning::SÉLECTION PARTIELLE : ce verdict ne vaut pas celui de la garde entière.")
    rouges = jouer_tout(SCRIPT, noms_s)
    for nom, fautes in rouges.items():
        for faute in fautes:
            erreurs.append(f"{nom}: {faute}")
    joue_m = "--sans-mutants" not in sys.argv and not (noms_s is not None and noms_m is None)
    if joue_m:
        for nom, motif, remplacement, attendus in MUTANTS:
            if noms_m is not None and nom not in noms_m:
                continue
            if src.count(motif) != 1:
                erreurs.append(f"mutant {nom} : motif présent {src.count(motif)} fois (1 attendu) — garde périmée")
                continue
            with tempfile.TemporaryDirectory() as tmp:
                mutant = os.path.join(tmp, "respond.sh")
                with open(mutant, "w", encoding="utf-8") as f:
                    f.write(src.replace(motif, remplacement))
                r = jouer_tout(mutant, set(attendus))
            manques = [a for a in attendus if a not in r]
            if manques:
                erreurs.append(f"mutant {nom} : SURVIT à {manques}")
            else:
                print(f"mutant {nom} : rouge sur {sorted(r)}")
    if erreurs:
        for e in erreurs:
            print(f"::error::{e}")
        print(f"\n{len(erreurs)} défaut(s) : le répondeur n'applique pas la durée servie, ou lit un refus comme une file.")
        return 1
    print(f"{len(SCENARIOS) if noms_s is None else len(noms_s)} scénarios verts sur respond.sh"
          + (f" ; {len(MUTANTS) if noms_m is None else len(noms_m)} mutants nommés tous rouges." if joue_m
             else " (mutants non joués)."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
