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
refusée dite au journal ; nft absent de l'hôte : ni sondé ni tenté. Mutants `unban_*` et
`nft_unban_leaves_the_ttl_set` de `MUTANTS`, chacun rouge sur ses scénarios.

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
#   absent_code:<n> écrit l'absence sur la sortie d'erreur et sort avec le code <n> (bords 125 à 129).
# Les SONDES `list table inet plume` et `list set inet plume blocklist_ttl` : un objet absent (NFT_ETAT `neuf`, ou
# `ancien` pour le set à durée) écrit l'absence MESURÉE (« No such file or directory », traduite hors locale C) et sort
# en code 1 ; NFT_SONDES_REFUSEES="table set" (l'un, l'autre ou les deux) rend la sonde REFUSÉE (« Operation not
# permitted », code 1), que l'objet existe ou non.
BOUCHON_NFT = r"""#!/bin/sh
printf '%s\n' "$*" >> "$TRACE_ENFORCEMENT.nft"
case "${LC_ALL:-${LC_MESSAGES:-${LANG:-C}}}" in
  C|POSIX|C.*) ENOENT='No such file or directory'; EEXIST='File exists' ;;
  *) ENOENT='Aucun fichier ou dossier de ce type'; EEXIST='Le fichier existe' ;;
esac
refus_de_sonde() { printf 'Error: Could not process rule: Operation not permitted\n%s\n' "$*" >&2; exit 1; }
case "$*" in
  "list table inet plume") case " ${NFT_SONDES_REFUSEES:-} " in *" table "*) refus_de_sonde "$*" ;; esac ;;
  "list set inet plume blocklist_ttl") case " ${NFT_SONDES_REFUSEES:-} " in *" set "*) refus_de_sonde "$*" ;; esac ;;
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


class Central:
    """Faux central. mode : 'demon' (JSON par ligne ssi Accept le nomme), 'tsv' (central antérieur),
    'statut' (statut, type, corps fixés). Journalise les en-têtes Accept et les verdicts remis."""

    def __init__(self, mode, actions=(), lignes_json=None, statut=None, type_contenu=None, corps=None,
                 longueur_annoncee=None, statut_remise=200):
        self.mode, self.actions, self.lignes_json = mode, list(actions), lignes_json
        self.statut, self.type_contenu, self.corps = statut, type_contenu, corps
        # longueur_annoncee : Content-Length MENTI (plus grand que le corps) => transfert tronqué côté curl.
        self.longueur_annoncee, self.statut_remise = longueur_annoncee, statut_remise
        self.accepts, self.verdicts = [], []
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
                central.verdicts.append(json.loads(self.rfile.read(n).decode("utf-8")))
                co = b'{"ok":true}'
                self.send_response(central.statut_remise)
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
          piege_python=False, rejeu_initial=None, faux_binaires=None):
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
               "PLUME_RESPONDER_ALLOW": epargne, "PLUME_STATE": tmp, "TRACE_ENFORCEMENT": trace,
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
        try:
            # Sorties décodées avec remplacement : un script (ou un mutant) qui coupe au milieu d'un caractère écrit un
            # journal invalide ; c'est le verdict remis qui est jugé, l'instrument ne doit pas tomber dessus.
            p = subprocess.run([shutil.which("sh"), script], env=env, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=DELAI_D_UN_TOUR_S, cwd=cwd)
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
]


def jouer_tout(script, noms=None):
    rouges = {}
    for nom, s in SCENARIOS.items():
        if noms is not None and nom not in noms:
            continue
        fautes = s(script)
        if fautes:
            rouges[nom] = fautes
    return rouges


def coherence_du_contrat(src):
    f = []
    exiger(f, f'TYPE_FILE_JSON="{TYPE_JSON}"' in src, f"respond.sh ne demande pas le type du démon ({TYPE_JSON})")
    for lecteur, motif in (("jq", f"$o.ban_ttl_s > {BORNE}"), ("python3", f"BORNE_DUREE = {BORNE}")):
        exiger(f, motif in src, f"la borne du lecteur {lecteur} n'est pas celle du démon ({BORNE}) : `{motif}` absent")
    return f


def main():
    src = open(SCRIPT, encoding="utf-8").read()
    erreurs = coherence_du_contrat(src)
    rouges = jouer_tout(SCRIPT)
    for nom, fautes in rouges.items():
        for faute in fautes:
            erreurs.append(f"{nom}: {faute}")
    if "--sans-mutants" not in sys.argv:
        for nom, motif, remplacement, attendus in MUTANTS:
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
    print(f"{len(SCENARIOS)} scénarios verts sur respond.sh"
          + (f" ; {len(MUTANTS)} mutants nommés tous rouges." if "--sans-mutants" not in sys.argv else " (mutants non joués)."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
