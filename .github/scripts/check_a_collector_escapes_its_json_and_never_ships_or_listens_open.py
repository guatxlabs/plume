#!/usr/bin/env python3
"""Un capteur échappe ce qu'il met dans son JSON, n'expédie pas en clair vers un hôte distant, et son
relais ne s'ouvre jamais sans jeton — garde de CI (`P10.32-i`).

LES DÉFAUTS QUE CETTE GARDE REND NON-ÉCRIVABLES
-----------------------------------------------
(a) `clamav.sh` et `yara.sh` assemblaient la clé `dedup` avec le NOM DU FICHIER, sans `json_escape`. Un
    fichier nommé `x","severity":0,"category":"info","z":"` fermait la chaîne et posait ses propres
    clés : la clé dupliquée gagne au central, une détection de logiciel malveillant devenait une
    information de sévérité nulle. Un nom fini par un antislash rendait l'enveloppe ENTIÈRE illisible,
    et le démon la rejette en bloc. Même forme dans `bans.sh` (adresse et clé), `vuln.sh` et
    `imgdrift.sh` (clé), et dans `crowdsec.sh` (adresse `.source.value` et id d'alerte de la LAPI).
(c) `bans.sh` sans aucun backend (ni fail2ban, ni cscli lisible) publiait quand même le battement
    « 0 ban(s) actif(s) » : un capteur qui ne surveille rien se disait vivant.
(d) `ship.sh` acceptait `http://` vers un hôte distant (jeton et événements en clair), et son
    éviction parcourait `for f in $(ls …)` : un nom à espace éclatait en deux mots dont l'un, relatif,
    était supprimé HORS du spool ; un lien symbolique du spool était expédié (le contenu de sa cible
    partait au central).
(e) `minio-audit-relay.py` avec un jeton vide, absent ou illisible était OUVERT (un avertissement), et
    comparait le jeton par `!=`.

CE QUE LA GARDE FAIT
--------------------
Elle JOUE les scripts LIVRÉS dans un bac : `PATH` réduit à un répertoire où vivent les outils de base
et des exécutables FACTICES (`clamscan`, `yara`, `trivy`, `skopeo`, `fail2ban-client`, `kubectl`,
`cscli`, `curl`) qui rendent des sorties fabriquées ; spool et état dans un répertoire temporaire. Les
capteurs sont joués sous CHAQUE awk présent (gawk, mawk), lié en `awk` dans le bac.
  · noms hostiles (guillemet qui forge `severity`/`category`, antislash final, guillemet seul) dans
    clamav, yara, vuln, imgdrift, bans (fail2ban et CrowdSec) et les alertes de crowdsec.sh
    (adresse et id) : chaque enveloppe se lit en JSON
    STRICT (une clé dupliquée est une faute), `severity` et `category` sont celles du capteur, `dedup`
    décodée porte le nom tel quel ;
  · bans sans backend, et avec un cscli sans jq : un aveu `unavailable`/`missing-dependency` de la
    source `fail2ban`, AUCUN battement ; bans avec fail2ban hôte, fail2ban du conteneur mail
    (`PLUME_MAIL_F2B`) ou CrowdSec : événement et battement OCTET POUR OCTET dans la forme livrée ;
  · ship : `http://` distant (avec et sans identité dans l'URL, sans schéma, majuscules, faux
    préfixe `127.`, identité `localhost@`, `@127.0.0.1` placé APRÈS un `/`, un `?` ou un `#` — chacune
    des trois coupures de l'autorité est exercée —, adresse `127.` à point doublé ou final, schéma
    illisible) REFUSÉ — code non nul, `REFUS` sur stderr, curl jamais appelé, spool intact même
    au-dessus du plafond, mot de passe de l'URL jamais imprimé ; opt-in `PLUME_SHIP_ALLOW_PLAINTEXT=1`
    expédie avec un avertissement, et le succès ne nomme le central que par schéma et hôte (ni en
    clair, ni en `https://`) ; boucle locale (127.0.0.1, ::1, localhost, LOCALHOST, identité devant
    127.0.0.1) et `https://` expédient sans un mot ; un lien symbolique n'est ni expédié ni supprimé,
    un répertoire est ignoré (jamais passé à `--data-binary`, passage en code 0), un nom à espace part, un spool dont le CHEMIN porte un espace est
    expédié et évincé entier ; l'éviction ne supprime rien hors du spool, n'évince ni un lien, ni une
    FIFO nommée en `.json`, ni un fichier hors motif, et l'aveu porte le compte RÉEL (pas le surplus prévu) ;
  · relais : jeton absent, vide, blanc, illisible (un répertoire) ou non UTF-8 -> refus de démarrer,
    code non nul, message nommé et non une trace d'exception ; jeton posé -> GET 200, POST sans jeton ou faux 401, POST juste 200 et événement au
    spool, jeton devenu vide en cours de route -> 503 ; jeton NON ASCII sous `LC_ALL=C`,
    `PYTHONCOERCECLOCALE=0`, `-X utf8=0` -> démarre et l'accepte (lecture en UTF-8 fixe). Puis, chargé en processus, la comparaison
    passe par `hmac.compare_digest` (espion posé sur le module : un `!=` ne l'appelle pas), et
    `autorisation_acceptee(…, "")` rend False en appel direct.

L'INSTRUMENT SE VALIDE AVANT DE CONCLURE
----------------------------------------
Sans `sh`, sans `jq`, sans awk exercé, ou si un script est introuvable, la garde REFUSE DE CONCLURE
(code 2). Chaque scénario vérifie que son faux outil a bien été appelé : un bouchon muet ferait
passer un capteur aveugle pour un capteur sûr.

CE QU'ELLE NE TIENT PAS
-----------------------
· Les modes k3s des capteurs (`k3s kubectl`) ne sont pas joués : seul `kubectl` l'est, la commande
  est la même.
· Un `cscli` présent SANS jq à côté d'un fail2ban lisible garde la forme livrée (le battement compte
  les seuls bans fail2ban) : ce sous-total n'est pas avoué, et cette garde ne le juge pas.
· Le transport n'est jugé que par son schéma et son hôte : la validité du certificat `https://` est
  l'affaire de curl et de `PLUME_TLS_CACERT`.
· LE CLAIR N'EST REFUSÉ QUE PAR `ship.sh`. `respond.sh`, `prom-scrape.sh` et `engagement-adapter.sh`
  envoient le même `PLUME_TOKEN` au même `PLUME_CENTRAL` (`bootstrap-agent.sh` recopie les deux dans
  `responder.conf`) et acceptent `http://` distant sans un mot ; `respond.sh` y RÉCUPÈRE en plus des
  actions qu'il exécute en root. Ce reste n'est ni corrigé ni joué ici.
· Les autres capteurs qui posent `src_ip` brut le tirent d'un motif borné (`SRC=[0-9A-Fa-f.:]*` de
  ufw, portscan, origin-drop ; `[0-9.]*` d'auditd ; adresses de conntrack), SAUF `kube-audit.sh`
  (motif `[^"]+` après `"sourceIPs":[`) : un antislash final y passerait. La valeur vient de l'apiserver, pas
  d'un tiers ; ce reste n'est pas joué ici.
· `crowdsec.sh` n'est joué que pour ses alertes : santé, hub et acquisition ne le sont pas ici.
· Le temps constant de la comparaison n'est pas MESURÉ (un chronomètre frapperait dans les deux
  sens) : la garde exige l'appel de la primitive à temps constant.

Sortie : 0 tenu · 1 au moins une propriété violée · 2 l'instrument REFUSE DE CONCLURE.
"""
import glob
import hashlib
import hmac as hmac_de_la_garde
import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
COL = os.path.join(RACINE, "collectors")
LIB = os.path.join(COL, "lib.sh")
RELAIS = os.path.join(COL, "minio-audit-relay.py")
NOM = "check_a_collector_escapes_its_json_and_never_ships_or_listens_open"

OUTILS = ["date", "mktemp", "cat", "grep", "dirname", "basename", "cksum", "cut", "mv", "rm", "mkdir",
          "iconv", "head", "tail", "sed", "tr", "sync", "chmod", "printf", "env", "wc", "sort", "ls",
          "touch", "test", "[", "find", "xargs", "stat", "sha256sum", "jq", "true", "false", "od"]
AWK_EXERCES = ("gawk", "mawk")

# Noms HOSTILES : chacun casse une forme différente d'assemblage brut.
FORGE = 'x","severity":0,"category":"info","z":"'      # ferme la chaîne, pose ses clés
ANTISLASH = 'fin\\'                                      # antislash final : échappe le guillemet fermant
GUILLEMET = 'a"b'

fautes = []


def refus(msg):
    print(f"::error::{NOM} : REFUSE DE CONCLURE — {msg}")
    sys.exit(2)


def faute(scen, msg):
    fautes.append(f"[{scen}] {msg}")


def _sans_doublon(paires):
    vus = {}
    for k, v in paires:
        if k in vus:
            raise ValueError(f"clé dupliquée {k!r}")
        vus[k] = v
    return vus


def lire_strict(txt):
    return json.loads(txt, object_pairs_hook=_sans_doublon)


def enveloppes(spool):
    """Rend [(nom, enveloppe | None, texte, erreur)] des enveloppes visibles du spool."""
    out = []
    for fp in sorted(glob.glob(os.path.join(spool, "*.json"))):
        if not os.path.isfile(fp):   # une FIFO posée par l'épreuve bloquerait `open` : seuls les fichiers
            continue
        with open(fp, encoding="utf-8", errors="surrogateescape") as f:
            txt = f.read()
        try:
            out.append((os.path.basename(fp), lire_strict(txt), txt, None))
        except ValueError as e:
            out.append((os.path.basename(fp), None, txt, str(e)))
    return out


def evenements(scen, spool):
    evs, textes = [], []
    for nom, env, txt, err in enveloppes(spool):
        if env is None:
            faute(scen, f"enveloppe {nom} illisible en JSON strict ({err}) : {txt[:240]!r}")
            continue
        textes.append(txt)
        evs.extend(env.get("events", []))
    return evs, textes


FAUX = {
    "clamscan": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
for a; do case "$a" in -*) continue ;; esac; printf '%s: Eicar-Signature FOUND\n' "$a"; done
exit 1
""",
    "yara": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
for a; do l=$a; done
while IFS= read -r p; do printf 'R1 [t1] %s\n' "$p"; done < "$l"
""",
    "trivy": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
cat "$FAKE_DIR/trivy.out"
""",
    "skopeo": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
cat "$FAKE_DIR/digest"
""",
    "fail2ban-client": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
if [ "$#" -eq 1 ]; then cat "$FAKE_DIR/f2b/status"; else cat "$FAKE_DIR/f2b/jail.$2"; fi
""",
    "kubectl": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ "$#" -gt 0 ] || exit 1
shift
[ "$1" = fail2ban-client ] || exit 1
if [ "$#" -eq 2 ]; then cat "$FAKE_DIR/mail/status"; else cat "$FAKE_DIR/mail/jail.$3"; fi
""",
    "cscli": r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
[ "$*" = "decisions list -o json" ] || exit 1
cat "$FAKE_DIR/decisions.json"
""",
    "curl": r"""#!/bin/sh
cat >/dev/null
url=""; fichier=""; prec=""
for a; do
  [ "$prec" = "--data-binary" ] && fichier=${a#@}
  prec=$a; url=$a
done
printf '%s\n' "$url" >> "$FAKE_DIR/curl.urls"
printf '%s\n' "$fichier" >> "$FAKE_DIR/curl.fichiers"
# seul un fichier régulier est lu : une FIFO postée par erreur bloquerait `cat` (elle est journalisée ci-dessus)
if [ -f "$fichier" ]; then cat "$fichier" >> "$FAKE_DIR/curl.corps"; printf '\n' >> "$FAKE_DIR/curl.corps"; fi
cat "$FAKE_DIR/code"
""",
}


class Bac:
    def __init__(self, base, awk, faux=(), sans=()):
        self.d = tempfile.mkdtemp(dir=base)
        self.bin = os.path.join(self.d, "bin")
        self.fake = os.path.join(self.d, "fake")
        self.spool = os.path.join(self.d, "spool")
        self.etat = os.path.join(self.d, "etat")
        for p in (self.bin, self.fake, self.spool, self.etat):
            os.makedirs(p)
        os.symlink(SH, os.path.join(self.bin, "sh"))
        if awk:
            os.symlink(awk, os.path.join(self.bin, "awk"))
        for o in OUTILS:
            if o in sans:
                continue
            p = shutil.which(o)
            if p:
                os.symlink(p, os.path.join(self.bin, o))
        for nom in faux:
            p = os.path.join(self.bin, nom)
            with open(p, "w") as f:
                f.write(FAUX[nom])
            os.chmod(p, stat.S_IRWXU)

    def poser(self, rel, contenu):
        p = os.path.join(self.fake, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(contenu)

    def appels(self):
        p = os.path.join(self.fake, "journal")
        return open(p).read().count("appel") if os.path.exists(p) else 0

    def jouer(self, script, env_plus=None, cwd=None):
        env = {"PATH": self.bin, "FAKE_DIR": self.fake, "PLUME_SPOOL": self.spool, "PLUME_STATE": self.etat,
               "PLUME_LIB": LIB, "LC_ALL": "C.UTF-8", "HOME": self.d}
        env.update(env_plus or {})
        return subprocess.run([SH, os.path.join(COL, script)], env=env, capture_output=True, text=True,
                              timeout=120, cwd=cwd or self.d)


def exiger_appel(scen, bac):
    if bac.appels() == 0:
        refus(f"[{scen}] le faux outil n'a jamais été appelé : le scénario ne mesure rien")


def juger_detections(scen, evs, source, categorie, severites, attendus_dedup):
    """Chaque événement de `source` a la catégorie et une sévérité attendues ; les dedup décodées
    sont EXACTEMENT `attendus_dedup`."""
    vus = [e for e in evs if e.get("source") == source]
    for e in vus:
        if e.get("category") != categorie:
            faute(scen, f"category={e.get('category')!r} au lieu de {categorie!r} : {e}")
        if e.get("severity") not in severites:
            faute(scen, f"severity={e.get('severity')!r} hors de {sorted(severites)} : {e}")
    dd = sorted(e.get("dedup", "") for e in vus)
    if dd != sorted(attendus_dedup):
        faute(scen, f"dedup {dd!r} au lieu de {sorted(attendus_dedup)!r}")


# --- (a)(b) capteurs à noms hostiles ------------------------------------------------------------------
def scen_clamav(base, awk, tag):
    scen = f"clamav/{tag}"
    bac = Bac(base, awk, faux=("clamscan",))
    scan = os.path.join(bac.d, "scan")
    os.makedirs(scan)
    noms = [FORGE, ANTISLASH, GUILLEMET, "sain.bin"]
    for n in noms:
        open(os.path.join(scan, n), "w").close()
    r = bac.jouer("clamav.sh", {"PLUME_CLAMAV_PATHS": scan})
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    juger_detections(scen, evs, "clamav", "malware", {4},
                     [f"clamav-{scan}/{n}-Eicar-Signature" for n in noms])


def scen_yara(base, awk, tag):
    scen = f"yara/{tag}"
    bac = Bac(base, awk, faux=("yara",))
    regles = os.path.join(bac.d, "regles")
    os.makedirs(regles)
    open(os.path.join(regles, "a.yar"), "w").close()
    scan = os.path.join(bac.d, "scan")
    os.makedirs(scan)
    noms = [FORGE, ANTISLASH, GUILLEMET]
    for n in noms:
        open(os.path.join(scan, n), "w").close()
    r = bac.jouer("yara.sh", {"PLUME_YARA_RULES": regles, "PLUME_YARA_PATHS": scan,
                              "PLUME_YARA_PRUNE": os.path.join(bac.d, "rien")})
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    att = []
    for n in noms:
        p = f"{scan}/{n}"
        att.append(f"yara-R1|{p}|{int(os.stat(p).st_mtime)}")
    juger_detections(scen, evs, "yara", "malware", {4}, att)
    for e in evs:
        if e.get("source") == "yara" and (e.get("fields") or {}).get("file") not in [f"{scan}/{n}" for n in noms]:
            faute(scen, f"fields.file ne porte pas le nom : {e.get('fields')}")
    vide = hashlib.sha256(b"").hexdigest()
    for e in evs:
        if e.get("source") == "yara" and (e.get("fields") or {}).get("sha256") != vide:
            faute(scen, f"fields.sha256 n'est pas l'empreinte du fichier : {e.get('fields')}")


def scen_vuln(base, awk, tag):
    scen = f"vuln/{tag}"
    bac = Bac(base, awk, faux=("trivy",))
    # `vuln.sh` passe l image par `awk -v`, qui interprete les antislashs : l image porte le guillemet,
    # l antislash final est porte par le paquet (lu par `$0`, sans interpretation).
    img = "reg/img" + FORGE
    bac.poser("trivy.out", f"CRITICAL\tCVE-0001\t{FORGE}\t1.0\t-\nHIGH\tCVE-0002\t{ANTISLASH}\t1.0\t2.0\n"
                           f"HIGH\tCVE-0003\t{GUILLEMET}\t1.0\t2.0\n")
    r = bac.jouer("vuln.sh", {"PLUME_VULN_IMAGES": img})
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    juger_detections(scen, evs, "vuln", "vuln", {3, 4},
                     [f"vuln-{img}|CVE-0001|{FORGE}", f"vuln-{img}|CVE-0002|{ANTISLASH}",
                      f"vuln-{img}|CVE-0003|{GUILLEMET}"])
    crit = [e for e in evs if e.get("source") == "vuln" and "CVE-0001" in e.get("dedup", "")]
    if not crit or crit[0].get("severity") != 4:
        faute(scen, f"la CVE CRITICAL n'a pas gardé sa sévérité 4 : {crit}")


def scen_imgdrift(base, awk, tag):
    scen = f"imgdrift/{tag}"
    bac = Bac(base, awk, faux=("skopeo",))
    img = "reg/b" + ANTISLASH
    env = {"PLUME_IMGDRIFT_IMAGES": img}
    bac.poser("digest", "sha256:aaaa\n")
    r1 = bac.jouer("imgdrift.sh", env)
    dig = "sha256:" + FORGE
    bac.poser("digest", dig + "\n")
    r2 = bac.jouer("imgdrift.sh", env)
    exiger_appel(scen, bac)
    for r in (r1, r2):
        if r.returncode != 0:
            faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    juger_detections(scen, evs, "update", "update", {1}, [f"update-{img}-{dig}"])


# --- (b)(c) bans ----------------------------------------------------------------------------------------
F2B_STATUS = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"


def f2b_jail(ips):
    return ("Status for the jail: sshd\n|- Filter\n`- Actions\n   |- Currently banned:\t%d\n"
            "   `- Banned IP list:\t%s\n" % (len(ips), " ".join(ips)))


def battements(evs):
    return [e for e in evs if e.get("source") == "fail2ban" and e.get("category") == "health"]


def aveux_indispo(evs, source):
    return [e for e in evs if e.get("category") == "config" and (e.get("fields") or {}).get("collector") == source
            and (e.get("fields") or {}).get("collect_status") == "unavailable"]


def scen_bans_sans_backend(base, awk, tag):
    for nom, faux, sans, env, mot in (
            ("aucun", (), (), {}, None),
            ("cscli-sans-jq", ("cscli",), ("jq",), {}, "jq"),
            ("mail-sans-pod", ("kubectl",), (), {"PLUME_MAIL_F2B": "1"}, "PLUME_MAIL_F2B")):
        scen = f"bans-{nom}/{tag}"
        bac = Bac(base, awk, faux=faux, sans=sans)
        if "cscli" in faux:
            env = dict(env, PLUME_CSCLI=os.path.join(bac.bin, "cscli"))
        r = bac.jouer("bans.sh", env)
        if r.returncode != 0:
            faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
        evs, _ = evenements(scen, bac.spool)
        if battements(evs):
            faute(scen, f"battement publié sans aucun backend : {battements(evs)}")
        if any("active_bans" in (e.get("fields") or {}) for e in evs):
            faute(scen, "un compteur `active_bans` est publié alors que rien n'a été compté")
        av = aveux_indispo(evs, "fail2ban")
        if len(av) != 1 or av[0]["fields"].get("reason") != "missing-dependency":
            faute(scen, f"aveu unavailable/missing-dependency de fail2ban absent ou faux : {av}")
        elif mot and mot not in av[0]["fields"].get("detail", ""):
            faute(scen, f"l'aveu ne nomme pas {mot!r} : {av[0]['fields'].get('detail')!r}")


def ban_attendu(ts, source, ip, label):
    b = ts // 3600
    return ('{"ts":%d,"source":"%s","category":"ban","severity":3,"message":"BAN actif %s (%s)",'
            '"src_ip":"%s","dedup":"ban-%s-%s-%d","fields":{"action":"ban"}}' % (ts, source, ip, label, ip, source, ip, b))


def battement_attendu(ts, n):
    return ('{"ts":%d,"source":"fail2ban","category":"health","severity":0,"message":"bans santé: %d ban(s) actif(s)",'
            '"fields":{"active_bans":%d}}' % (ts, n, n))


def juger_bans_presents(scen, bac, r, sains, hostiles, source, n):
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    envs = [e for e in enveloppes(bac.spool) if e[0].startswith("bans-")]
    evs, _ = evenements(scen, bac.spool)
    if len(envs) != 1 or envs[0][1] is None:
        faute(scen, f"enveloppe bans absente ou illisible : {[(e[0], e[3]) for e in envs]}")
        return
    txt, ts = envs[0][2], envs[0][1]["ts"]
    for ip, label in sains:
        if ban_attendu(ts, source, ip, label) not in txt:
            faute(scen, f"la forme livrée de l'événement {ip} a changé : {txt[:400]!r}")
    if battement_attendu(ts, n) not in txt:
        faute(scen, f"le battement n'est pas « {n} ban(s) actif(s) » dans la forme livrée : {txt[-300:]!r}")
    if aveux_indispo(evs, "fail2ban"):
        faute(scen, "aveu d'indisponibilité alors qu'un backend est présent et lu")
    bans = [e for e in evs if e.get("category") == "ban"]
    for e in bans:
        if e.get("severity") != 3 or e.get("source") != source:
            faute(scen, f"ban réécrit : {e}")
    ips = sorted(e.get("src_ip") for e in bans)
    if ips != sorted([i for i, _ in sains] + hostiles):
        faute(scen, f"src_ip {ips!r} au lieu de {sorted([i for i, _ in sains] + hostiles)!r}")
    for e in bans:
        if not e.get("dedup", "").startswith(f"ban-{source}-{e.get('src_ip')}-"):
            faute(scen, f"dedup ne porte pas l'adresse : {e.get('dedup')!r}")


def scen_bans_presents(base, awk, tag):
    hostile_f2b = "198.51.100.7" + FORGE
    # fail2ban hôte
    scen = f"bans-f2b-hote/{tag}"
    bac = Bac(base, awk, faux=("fail2ban-client",))
    bac.poser("f2b/status", F2B_STATUS)
    bac.poser("f2b/jail.sshd", f2b_jail(["192.0.2.1", hostile_f2b]))
    r = bac.jouer("bans.sh")
    juger_bans_presents(scen, bac, r, [("192.0.2.1", "sshd")], [hostile_f2b], "fail2ban", 2)
    # fail2ban du conteneur mail
    scen = f"bans-f2b-mail/{tag}"
    bac = Bac(base, awk, faux=("kubectl",))
    bac.poser("mail/status", "Status\n|- Number of jail:\t1\n`- Jail list:\tpostfix\n")
    bac.poser("mail/jail.postfix", f2b_jail(["203.0.113.9"]))
    r = bac.jouer("bans.sh", {"PLUME_MAIL_F2B": "1", "PLUME_MAIL_F2B_POD": "mailserver-0"})
    juger_bans_presents(scen, bac, r, [("203.0.113.9", "mail/postfix")], [], "fail2ban", 1)
    # CrowdSec
    scen = f"bans-crowdsec/{tag}"
    bac = Bac(base, awk, faux=("cscli",))
    # `jq @tsv` double un antislash (forme livree, hors de cette cle) : le guillemet seul est exerce ici.
    hostile_cs = "192.0.2.51" + GUILLEMET
    bac.poser("decisions.json", json.dumps([{"decisions": [
        {"value": "192.0.2.50", "scenario": "crowdsecurity/ssh-bf"},
        {"value": hostile_cs, "scenario": "x"},
        {"value": "192.0.2.52" + FORGE, "scenario": "y"}]}]))
    r = bac.jouer("bans.sh", {"PLUME_CSCLI": os.path.join(bac.bin, "cscli")})
    juger_bans_presents(scen, bac, r, [("192.0.2.50", "crowdsecurity/ssh-bf")],
                        [hostile_cs, "192.0.2.52" + FORGE], "crowdsec", 3)


# --- (b) crowdsec.sh : alertes de la LAPI ------------------------------------------------------------
CSCLI_ALERTES = r"""#!/bin/sh
echo appel >> "$FAKE_DIR/journal"
[ "$1 $2" = "alerts list" ] || exit 1
cat "$FAKE_DIR/alerts.json"
"""


def scen_crowdsec_alertes(base, awk, tag):
    scen = f"crowdsec-alertes/{tag}"
    bac = Bac(base, awk)
    cs = os.path.join(bac.bin, "cscli")
    with open(cs, "w") as f:
        f.write(CSCLI_ALERTES)
    os.chmod(cs, stat.S_IRWXU)
    # `jq @tsv` double un antislash (forme livrée) : le guillemet est exercé, par l'adresse ET par l'id.
    hostile_ip = "192.0.2.52" + FORGE
    hostile_id = "9" + FORGE
    bac.poser("alerts.json", json.dumps([
        {"id": 1, "source": {"value": "192.0.2.50"}, "scenario": "crowdsecurity/ssh-bf"},
        {"id": 2, "source": {"value": hostile_ip}, "scenario": "y"},
        {"id": 3, "source": {"value": "192.0.2.53" + GUILLEMET}, "scenario": "z"},
        {"id": hostile_id, "source": {"value": "192.0.2.54"}, "scenario": "w"}]))
    r = bac.jouer("crowdsec.sh", {"PLUME_CSCLI": cs})
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    # santé, hub et acquisition (absents de ce faux cscli) publient leurs propres événements et aveux :
    # seules les alertes, `dedup` en `crowdsec-<id>`, sont jugées ici.
    evs = [e for e in evs if str(e.get("dedup", "")).startswith("crowdsec-")]
    if len(evs) != 4:
        faute(scen, f"{len(evs)} alerte(s) publiée(s) au lieu de 4 : {evs}")
    juger_detections(scen, evs, "crowdsec", "network", {3},
                     ["crowdsec-1", "crowdsec-2", "crowdsec-3", "crowdsec-" + hostile_id])
    ips = sorted(e.get("src_ip", "") for e in evs if e.get("source") == "crowdsec" and e.get("category") == "network")
    att = sorted(["192.0.2.50", hostile_ip, "192.0.2.53" + GUILLEMET, "192.0.2.54"])
    if ips != att:
        faute(scen, f"src_ip {ips!r} au lieu de {att!r}")


# --- (d) ship -------------------------------------------------------------------------------------------
def bac_ship(base, code="202"):
    bac = Bac(base, None, faux=("curl",))
    bac.poser("code", code)
    return bac


def visibles(spool):
    return sorted(f for f in os.listdir(spool) if not f.startswith("."))


def appels_curl(bac):
    p = os.path.join(bac.fake, "curl.urls")
    return open(p).read().splitlines() if os.path.exists(p) else []


def fichiers_postes(bac):
    """Noms (base) des fichiers passés à `--data-binary` par chaque appel du faux curl."""
    p = os.path.join(bac.fake, "curl.fichiers")
    return [os.path.basename(l) for l in open(p).read().splitlines()] if os.path.exists(p) else []


def corps_curl(bac):
    p = os.path.join(bac.fake, "curl.corps")
    return open(p).read() if os.path.exists(p) else ""


def scen_ship(base):
    env_base = {"PLUME_TOKEN": "jeton-de-garde"}
    # témoin de l'instrument : https expédie, le faux curl est bien celui qui répond
    bac = bac_ship(base)
    bac_ok = bac
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="https://central.invalid:7000"))
    if not appels_curl(bac):
        refus("[ship] le faux curl n'a jamais été appelé sous https : l'épreuve ne mesure rien")
    if r.returncode != 0 or visibles(bac.spool) or "REFUS" in r.stderr or "AVERTISSEMENT" in r.stderr:
        faute("ship-https", f"https doit expédier sans un mot : rc={r.returncode} spool={visibles(bac.spool)} "
                            f"stderr={r.stderr[:200]!r}")
    if appels_curl(bac_ok) != ["https://central.invalid:7000/api/ingest"]:
        faute("ship-https", f"URL appelée {appels_curl(bac_ok)!r}")

    # REFUS : http distant, sous toutes ses formes
    for url in ("http://central.invalid:7000", "http://u:motdepasse-de-garde@192.0.2.10:7000/",
                "central.invalid:7000", "HTTP://192.0.2.10", "http://127.0.0.1.evil.invalid/",
                "http://localhost@192.0.2.10/", "http://127.0.0.1x/", "http://127.0.0.1.2/",
                "ftp://192.0.2.10/",
                # l'autorite s'arrete au premier `/`, `?` ou `#` : un `@` APRES n'est pas une identite
                # (curl vise `evil.invalid`, mesure) ; chaque URL retire l'une des trois coupures.
                "http://evil.invalid/@127.0.0.1:7000", "http://evil.invalid?@127.0.0.1/",
                "http://evil.invalid#@127.0.0.1/",
                "http://127..0.1/", "http://127.0.0./", "x:motdepasse-de-garde@h/a://b"):
        scen = f"ship-refus[{url}]"
        bac = bac_ship(base)
        for i in range(3):
            p = os.path.join(bac.spool, f"e{i}.json")
            open(p, "w").write("{}")
            os.utime(p, (time.time() - 100 + i,) * 2)
        r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL=url, PLUME_SPOOL_MAX_FILES="1"))
        if r.returncode == 0:
            faute(scen, "code 0 : le clair vers un hôte distant n'est pas refusé")
        if "REFUS" not in r.stderr:
            faute(scen, f"aucun refus nommé sur stderr : {r.stderr[:200]!r}")
        if "motdepasse-de-garde" in r.stderr + r.stdout:
            faute(scen, "le mot de passe de l'URL est imprimé")
        if appels_curl(bac):
            faute(scen, f"curl appelé malgré le refus : {appels_curl(bac)}")
        if visibles(bac.spool) != ["e0.json", "e1.json", "e2.json"]:
            faute(scen, f"spool non conservé : {visibles(bac.spool)}")

    # OPT-IN explicite
    scen = "ship-opt-in"
    bac = bac_ship(base)
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="http://192.0.2.10:7000", PLUME_SHIP_ALLOW_PLAINTEXT="1"))
    if r.returncode != 0 or visibles(bac.spool) or appels_curl(bac) != ["http://192.0.2.10:7000/api/ingest"]:
        faute(scen, f"l'opt-in n'expédie pas : rc={r.returncode} spool={visibles(bac.spool)} curl={appels_curl(bac)}")
    if "AVERTISSEMENT" not in r.stderr:
        faute(scen, "l'opt-in expédie en clair sans avertissement")
    for url, att in (("http://u:motdepasse-de-garde@192.0.2.10:7000", "http://192.0.2.10:7000"),
                     ("https://u:motdepasse-de-garde@central.invalid", "https://central.invalid")):
        scen = f"ship-identite-tue[{att}]"
        bac = bac_ship(base)
        open(os.path.join(bac.spool, "a.json"), "w").write("{}")
        r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL=url, PLUME_SHIP_ALLOW_PLAINTEXT="1"))
        if r.returncode != 0 or not appels_curl(bac):
            faute(scen, f"n'expédie pas : rc={r.returncode} curl={appels_curl(bac)} {r.stderr[:200]!r}")
        if "motdepasse-de-garde" in r.stderr + r.stdout:
            faute(scen, f"le mot de passe de l'URL est imprimé : {(r.stdout + r.stderr)[:300]!r}")
        if f"-> {att}" not in r.stdout:
            faute(scen, f"le succès ne nomme pas le central sans identité ({att}) : {r.stdout[:200]!r}")
    bac = bac_ship(base)
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="http://192.0.2.10:7000", PLUME_SHIP_ALLOW_PLAINTEXT="oui"))
    if r.returncode == 0 or appels_curl(bac):
        faute("ship-opt-in-flou", "une valeur d'opt-in autre que 1 ouvre le clair")

    # boucle locale : inchangé
    for url in ("http://127.0.0.1:7000", "http://localhost:7000", "http://[::1]:7000", "http://127.1.2.3:7000",
                "http://u@127.0.0.1:7000", "http://LOCALHOST:7000"):
        scen = f"ship-boucle[{url}]"
        bac = bac_ship(base)
        open(os.path.join(bac.spool, "a.json"), "w").write("{}")
        open(os.path.join(bac.spool, "j.ndjson"), "w").write("{}")
        r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL=url))
        if r.returncode != 0 or visibles(bac.spool) or "REFUS" in r.stderr or "AVERTISSEMENT" in r.stderr:
            faute(scen, f"la boucle locale doit expédier sans un mot : rc={r.returncode} spool={visibles(bac.spool)} "
                        f"stderr={r.stderr[:200]!r}")
        if sorted(appels_curl(bac)) != sorted([url + "/api/ingest", url + "/api/ingest/journal"]):
            faute(scen, f"URL appelées {appels_curl(bac)!r}")

    # parcours : lien symbolique, répertoire, nom à espace
    scen = "ship-parcours"
    bac = bac_ship(base)
    cible = os.path.join(bac.d, "secret-hors-spool")
    open(cible, "w").write("SECRET-CIBLE-DE-GARDE")
    os.symlink(cible, os.path.join(bac.spool, "lien.json"))
    os.mkdir(os.path.join(bac.spool, "rep.json"))
    open(os.path.join(bac.spool, "a b.json"), "w").write('{"ok":"espace"}')
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="https://central.invalid"))
    if "SECRET-CIBLE-DE-GARDE" in corps_curl(bac):
        faute(scen, "le contenu de la cible d'un lien symbolique a été expédié au central")
    if not os.path.islink(os.path.join(bac.spool, "lien.json")) or not os.path.exists(cible):
        faute(scen, "le lien symbolique ou sa cible a été supprimé")
    if not os.path.isdir(os.path.join(bac.spool, "rep.json")):
        faute(scen, "un répertoire du spool a disparu")
    # Le répertoire ne disparaît jamais (`rm -f` n'efface pas un répertoire) : ce qui l'IGNORE, c'est
    # qu'il n'est jamais passé à curl et que le passage finit sans erreur.
    if "a b.json" not in fichiers_postes(bac):
        refus(f"[{scen}] le faux curl ne journalise pas les fichiers postés : {fichiers_postes(bac)!r}")
    if "rep.json" in fichiers_postes(bac):
        faute(scen, f"un répertoire du spool a été posté au central : {fichiers_postes(bac)!r}")
    if r.returncode != 0:
        faute(scen, f"le parcours du spool finit en erreur : rc={r.returncode} {r.stderr[:200]!r}")
    if os.path.exists(os.path.join(bac.spool, "a b.json")) or '"espace"' not in corps_curl(bac):
        faute(scen, f"le nom à espace n'est pas expédié : spool={visibles(bac.spool)} rc={r.returncode} {r.stderr[:200]!r}")

    # spool dont le CHEMIN porte un espace : expédition et éviction le tiennent entier
    scen = "ship-spool-a-espace"
    bac = bac_ship(base)
    spool_esp = os.path.join(bac.d, "spool a espace")
    os.makedirs(spool_esp)
    for i, n in enumerate(("v1.json", "v2.json", "v3.json")):
        p = os.path.join(spool_esp, n)
        open(p, "w").write('{"v":"%s"}' % n)
        os.utime(p, (time.time() - 100 + i,) * 2)
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="https://central.invalid", PLUME_SPOOL=spool_esp,
                                  PLUME_SPOOL_MAX_FILES="2"))
    corps = corps_curl(bac)
    if r.returncode != 0 or '"v3.json"' not in corps or '"v1.json"' in corps:
        faute(scen, f"rc={r.returncode} corps={corps[:300]!r} stderr={r.stderr[:200]!r}")
    if [f for f in os.listdir(spool_esp) if f.startswith("v")]:
        faute(scen, f"le spool à espace n'est pas vidé : {os.listdir(spool_esp)}")

    # éviction : rien hors du spool, pas de lien, compte juste
    scen = "ship-eviction"
    bac = bac_ship(base, code="000")
    dehors = os.path.join(bac.d, "cwd")
    os.makedirs(dehors)
    open(os.path.join(dehors, "ABS.json"), "w").write("hors spool")
    cible = os.path.join(bac.d, "cible-lien")
    open(cible, "w").write("x")
    t0 = time.time() - 1000
    lien = os.path.join(bac.spool, "aa-lien.json")
    os.symlink(cible, lien)
    os.utime(lien, (t0 - 10,) * 2, follow_symlinks=False)
    # une FIFO nommée en `.json`, plus ancienne que tout : ni fichier régulier ni lien, jamais évincée
    # (c'est la moitié `[ -f ]` du filtre ; la moitié `[ ! -L ]` est tenue par le lien ci-dessus)
    fifo = os.path.join(bac.spool, "aa-fifo.json")
    os.mkfifo(fifo)
    os.utime(fifo, (t0 - 15,) * 2)
    noms = ["z ABS.json", "r1.json", "r2.json", "r3.json", "r4.json"]   # du plus ancien au plus récent
    for i, n in enumerate(noms):
        p = os.path.join(bac.spool, n)
        open(p, "w").write("{}")
        os.utime(p, (t0 + i,) * 2)
    # hors motif (le plus ancien de tous) : ni compté ni évincé
    p = os.path.join(bac.spool, "aaa-notes.txt")
    open(p, "w").write("x")
    os.utime(p, (t0 - 20,) * 2)
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="https://central.invalid", PLUME_SPOOL_MAX_FILES="2"),
                  cwd=dehors)
    if not os.path.exists(os.path.join(dehors, "ABS.json")):
        faute(scen, "l'éviction a supprimé un fichier HORS du spool (nom à espace éclaté)")
    if not os.path.islink(lien) or not os.path.exists(cible):
        faute(scen, "l'éviction a touché un lien symbolique ou sa cible")
    restants = [f for f in visibles(bac.spool) if not f.startswith("config-availability")]
    if not os.path.exists(fifo) or not stat.S_ISFIFO(os.stat(fifo).st_mode):
        faute(scen, "l'éviction a supprimé une FIFO nommée du spool (pas un fichier régulier)")
    if "aa-fifo.json" in fichiers_postes(bac):
        faute(scen, "une FIFO nommée du spool a été passée à curl (pas un fichier régulier)")
    if restants != ["aa-fifo.json", "aa-lien.json", "aaa-notes.txt", "r3.json", "r4.json"]:
        faute(scen, f"restent {restants}, attendu la FIFO, le lien, le fichier hors motif et les deux plus récents")
    av = [t for _, _, t, _ in enveloppes(bac.spool) if "spool-full" in t]
    if not av or "3 fichier(s) les plus anciens" not in av[0]:
        faute(scen, f"l'aveu spool-full ne porte pas le compte 3 : {[a[:200] for a in av]}")

    # compte RÉEL et non surplus prévu : des fichiers cachés (comptés par `find`, jamais listés ni
    # évincés) font un surplus de 3 dont un seul fichier est évinçable.
    scen = "ship-eviction-compte-reel"
    bac = bac_ship(base, code="000")
    for i, n in enumerate((".c1.json", ".c2.json", ".c3.json", "s1.json")):
        p = os.path.join(bac.spool, n)
        open(p, "w").write("{}")
        os.utime(p, (t0 + i,) * 2)
    r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL="https://central.invalid", PLUME_SPOOL_MAX_FILES="1"))
    av = [t for _, _, t, _ in enveloppes(bac.spool) if "spool-full" in t]
    if os.path.exists(os.path.join(bac.spool, "s1.json")):
        faute(scen, "le seul fichier évinçable n'est pas évincé")
    if not av or "1 fichier(s) les plus anciens" not in av[0]:
        faute(scen, f"l'aveu spool-full ne porte pas le compte réel 1 (surplus prévu 3) : {[a[:200] for a in av]}")


# --- (e) relais -----------------------------------------------------------------------------------------
def port_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def requete(port, methode, corps=None, jeton=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=corps, method=methode)
    if jeton is not None:
        req.add_header("Authorization", jeton)
    try:
        with urllib.request.urlopen(req, timeout=10) as rep:
            return rep.status
    except urllib.error.HTTPError as e:
        return e.code


RECORD = json.dumps({"api": {"name": "DeleteObject", "bucket": "example-backups", "object": "k", "status": "OK",
                             "statusCode": 204}, "requestID": "R-GARDE", "time": "2026-01-01T00:00:00Z"}).encode()


def scen_relais(base):
    d = tempfile.mkdtemp(dir=base)
    spool = os.path.join(d, "spool")
    os.makedirs(spool)
    jeton = os.path.join(d, "jeton")
    rep = os.path.join(d, "jeton-repertoire")
    os.makedirs(rep)

    def lancer(fichier, env_plus=None, drapeaux=()):
        port = port_libre()
        env = {"PATH": os.environ.get("PATH", ""), "PLUME_SPOOL": spool, "PLUME_MINIO_AUDIT_BIND": "127.0.0.1",
               "PLUME_MINIO_AUDIT_PORT": str(port), "PLUME_MINIO_AUDIT_TOKEN_FILE": fichier}
        env.update(env_plus or {})
        return port, subprocess.Popen([sys.executable, "-I", *drapeaux, RELAIS], env=env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

    def attendre_ecoute(scen, port, p):
        for _ in range(100):
            if p.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        refus(f"[{scen}] le relais n'écoute pas avec un jeton posé : {p.stderr.read()[:300] if p.poll() is not None else ''}")

    for nom, prep in (("absent", None), ("vide", ""), ("blanc", "  \n\t\n"), ("illisible", "REP"),
                      ("non-utf8", b"\xff\xfejeton\n")):
        scen = f"relais-jeton-{nom}"
        f = jeton + "-" + nom
        if prep == "REP":
            f = rep
        elif isinstance(prep, bytes):
            open(f, "wb").write(prep)
        elif prep is not None:
            open(f, "w").write(prep)
        port, p = lancer(f)
        try:
            _, err = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            faute(scen, "le relais a démarré (il écoute toujours) sans jeton")
            continue
        if p.returncode == 0:
            faute(scen, "code 0 sans jeton")
        if "REFUS" not in err or "Traceback" in err:
            faute(scen, f"aucun refus nommé (ou une trace d'exception à sa place) : {err[:200]!r}")

    # Jeton NON ASCII sous une locale C sans mode UTF-8 (ni coercition de locale, ni `-X utf8`) : le
    # relais lit son jeton en UTF-8 FIXE, il démarre et accepte ce jeton. Une lecture à l'encodage de
    # la locale (ASCII) le croirait illisible et refuserait de démarrer.
    scen = "relais-jeton-non-ascii-locale-c"
    jeton_na = jeton + "-non-ascii"
    with open(jeton_na, "w", encoding="utf-8") as f:
        f.write("j\u00e9ton-de-garde\n")
    port, p = lancer(jeton_na, {"LC_ALL": "C", "LANG": "C", "PYTHONCOERCECLOCALE": "0"}, ("-X", "utf8=0"))
    try:
        for _ in range(100):
            if p.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        if p.poll() is not None:
            faute(scen, f"le relais refuse de démarrer : rc={p.returncode} {p.stderr.read()[:300]!r}")
        else:
            # `urllib` émet l'en-tête en latin-1, `http.server` le relit en latin-1 : « é » fait l'aller-retour
            if requete(port, "POST", RECORD, "Bearer j\u00e9ton-de-garde") != 200:
                faute(scen, "POST avec le bon jeton non ASCII refusé")
            if requete(port, "POST", RECORD, "Bearer jeton-de-garde") != 401:
                faute(scen, "POST avec le jeton privé de son accent accepté")
    finally:
        p.kill()
        p.communicate()

    scen = "relais-jeton-pose"
    open(jeton, "w").write("jeton-de-garde\n")
    port, p = lancer(jeton)
    try:
        attendre_ecoute(scen, port, p)
        if requete(port, "GET") != 200:
            faute(scen, "GET de santé ne rend pas 200")
        if requete(port, "POST", RECORD) != 401:
            faute(scen, "POST sans jeton accepté")
        if requete(port, "POST", RECORD, "Bearer faux") != 401:
            faute(scen, "POST avec un faux jeton accepté")
        if requete(port, "POST", RECORD, "Bearer jeton-de-garde") != 200:
            faute(scen, "POST avec le bon jeton refusé")
        evs = []
        for fp in glob.glob(os.path.join(spool, "minio-audit-*.json")):
            evs.extend(json.load(open(fp)).get("events", []))
        if not any(e.get("dedup") == "minioaudit-R-GARDE" and e.get("severity") == 4 for e in evs):
            faute(scen, f"l'événement accepté n'est pas au spool : {evs}")
        open(jeton, "w").write("")
        code = requete(port, "POST", RECORD, "Bearer jeton-de-garde")
        # Le refus est NOMMÉ (503 « aucun jeton configuré ») et non confondu avec un faux jeton (401).
        if code != 503:
            faute(scen, f"jeton devenu vide en cours de route : {code} au lieu du refus 503")
        code = requete(port, "POST", RECORD)
        if code != 503:
            faute(scen, f"jeton devenu vide, requête sans jeton : {code} au lieu du refus 503")
    finally:
        p.kill()
        p.communicate()

    # comparaison à temps constant : espion sur `hmac` du module chargé
    scen = "relais-temps-constant"
    spec = importlib.util.spec_from_file_location("relais_sous_garde", RELAIS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    vrai = hmac_de_la_garde.compare_digest
    appels = []

    class Espion:
        @staticmethod
        def compare_digest(a, b):
            appels.append(1)
            return vrai(a, b)

    mod.hmac = Espion
    open(jeton, "w").write("jeton-de-garde\n")
    mod.TOKEN_FILE = jeton
    mod.SPOOL = spool
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        bon = requete(port, "POST", RECORD, "Bearer jeton-de-garde")
        mauvais = requete(port, "POST", RECORD, "Bearer jeton-de-gardX")
    finally:
        srv.shutdown()
        srv.server_close()
    if bon != 200 or mauvais != 401:
        faute(scen, f"verdicts en processus {bon}/{mauvais}, attendu 200/401")
    if len(appels) < 2:
        faute(scen, f"hmac.compare_digest appelé {len(appels)} fois pour 2 requêtes authentifiées : "
                    "la comparaison du jeton n'est pas à temps constant")
    # appel direct : un attendu vide ne s'accepte JAMAIS, même face à un en-tête vide ou absent
    for entete in ("", None, "Bearer "):
        if mod.autorisation_acceptee(entete, "") is not False:
            faute("relais-attendu-vide", f"autorisation_acceptee({entete!r}, '') ne rend pas False")


def main():
    global SH
    SH = shutil.which("dash") or shutil.which("sh")
    if not SH:
        refus("aucun `sh`")
    if not shutil.which("jq"):
        refus("aucun `jq` (bans/CrowdSec le requiert)")
    for s in ("clamav.sh", "yara.sh", "vuln.sh", "imgdrift.sh", "bans.sh", "crowdsec.sh", "ship.sh", "lib.sh",
              "minio-audit-relay.py"):
        if not os.path.isfile(os.path.join(COL, s)):
            refus(f"collectors/{s} introuvable")
    awks = [(a, shutil.which(a)) for a in AWK_EXERCES if shutil.which(a)]
    if not awks:
        refus(f"aucun awk exercé présent parmi {AWK_EXERCES}")
    base = tempfile.mkdtemp(prefix="plume-collecte-sure-")
    try:
        for tag, awk in awks:
            scen_clamav(base, awk, tag)
            scen_yara(base, awk, tag)
            scen_vuln(base, awk, tag)
            scen_imgdrift(base, awk, tag)
            scen_bans_sans_backend(base, awk, tag)
            scen_bans_presents(base, awk, tag)
            scen_crowdsec_alertes(base, awk, tag)
        scen_ship(base)
        scen_relais(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if fautes:
        for f in fautes:
            print(f"::error::{NOM} : {f}")
        print(f"{len(fautes)} faute(s).")
        return 1
    print(f"collecte sûre : JSON échappé sous {', '.join(t for t, _ in awks)} (clamav, yara, vuln, imgdrift, bans, crowdsec), "
          "aveu sans backend, clair distant refusé, parcours du spool sûr, relais fermé sans jeton.")
    return 0


SH = None

if __name__ == "__main__":
    sys.exit(main())
