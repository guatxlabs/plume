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

CE QUE CETTE GARDE NE TIENT PAS : un vrai CrowdSec, un vrai nft (noyau, borne du timeout) ou un vrai fail2ban
ne sont pas exercés — en particulier, qu'un `timeout 0s` donne un élément sans fin n'est pas mesuré sur un
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

OUTILS = ["cat", "sed", "tr", "grep", "date", "mkdir", "touch", "mktemp", "chmod", "mv", "rm", "dd", "cut",
          "wc", "sleep", "curl"]

BOUCHON = r"""#!/bin/sh
printf '%s\n' "$*" >> "$TRACE_ENFORCEMENT.NOM"
exit 0
"""
# nft : l'état de l'hôte est fixé par NFT_ETAT —
#   `ancien` (défaut) : la table `inet plume` existe (version antérieure), le set à durée NON ;
#   `neuf`            : ni table ni set (hôte jamais équipé) ;
#   `equipe`          : table ET set à durée déjà là (hôte équipé par cette version).
BOUCHON_NFT = r"""#!/bin/sh
printf '%s\n' "$*" >> "$TRACE_ENFORCEMENT.nft"
case "${NFT_ETAT:-ancien}:$*" in
  "ancien:list set inet plume blocklist_ttl") exit 1 ;;
  "neuf:list table inet plume"|"neuf:list set inet plume blocklist_ttl") exit 1 ;;
esac
exit 0
"""


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
        p = subprocess.run([shutil.which("sh"), script], env=env, capture_output=True, text=True, timeout=120,
                           cwd=cwd)
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
    """Une durée de repli qui COMMENCE comme une durée nft (`4hours`) est refusée entière, jamais posée."""
    c = Central("tsv", [ban(576, "203.0.113.64")])
    try:
        t = jouer(script, c, lecteurs=(), backend="nft", bouchons=("nft",), env_plus={"PLUME_BAN_DURATION": "4hours"})
    finally:
        c.fermer()
    f = []
    exiger(f, "add element" not in t.trace("nft"), f"`4hours` posé en nft : {t.trace('nft')!r}")
    verdict_est(f, t, 576, "failed", "illisible")
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
    exiger(f, "add element inet plume blocklist_ttl { 203.0.113.71 timeout 5400s }" in n, f"élément sans timeout servi : {n!r}")
    exiger(f, "add element inet plume blocklist {" not in n, f"ban PERMANENT posé dans l'ancien set : {n!r}")
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
    exiger(f, "add element" not in t.trace("nft"), f"un ban nft est posé avec une durée illisible : {t.trace('nft')!r}")
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
                    "add element inet plume blocklist_ttl { 203.0.113.32 timeout 600s }"):
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
        exiger(f, "add element" not in t.trace("nft"), f"PLUME_BAN_DURATION={valeur} : élément nft posé (timeout nul) : {t.trace('nft')!r}")
        verdict_est(f, t, i, "failed", "nulle")
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
    ("nft_ban_without_timeout", 'OUT=$(nft add element inet plume "$NFT_SET_TTL" "{ $t timeout $EFF_DUR }" 2>&1)',
     'OUT=$(nft add element inet plume blocklist "{ $t }" 2>&1)', ["nft_ttl_set_beside_the_permanent_one"]),
    ("nft_illegible_duration_not_refused",
     '      duree_lisible_par_nft "$EFF_DUR" || { OUT="duree $EFF_DUR illisible ou nulle comme timeout nft, rien pose"; return 1; }\n', "",
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
     '    if nft list set inet plume blocklist_ttl >/dev/null 2>&1; then r=$(nft delete element inet plume blocklist_ttl "{ $1 }" 2>&1 || true); OUT="$OUT [nft-ttl]$r"; fi\n',
     "", ["nft_unban_clears_the_ttl_set"]),
    ("nft_fresh_host_table_skipped", "  if ! nft list table inet plume >/dev/null 2>&1; then\n    nft add table",
     "  if false; then\n    nft add table", ["nft_fresh_host_table_created"]),
    ("nft_zero_duration_accepted", " && printf '%s' \"$1\" | grep -q '[1-9]'", "",
     ["nft_zero_fallback_never_permanent"]),
    ("queue_curl_failure_not_judged", 'if [ "$_file_rc" != 0 ] || [ "$_file_code" != 200 ]; then',
     'if [ "$_file_code" != 200 ]; then',
     ["queue_200_truncated_never_parsed_tsv", "queue_200_truncated_never_parsed_python3"]),
    ("queue_body_unbounded", '--max-filesize "$FILE_OCTETS_MAX" "$@"', '"$@"', ["queue_200_oversized_never_parsed"]),
    ("out_of_contract_line_reposted_while_pending", '        if verdict_en_attente_de_remise "$_r_2"; then\n',
     "        if false; then\n", ["out_of_contract_line_not_reposted_while_pending"]),
    ('nft_fallback_regex_unanchored', "grep -qE '^([0-9]+[dhms])+$'", "grep -qE '([0-9]+[dhms])+'",
     ['nft_fallback_unanchored_duration_refused']),
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
