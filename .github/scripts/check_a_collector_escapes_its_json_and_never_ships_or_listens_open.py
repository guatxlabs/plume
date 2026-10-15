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
(f) `P10.33-a` — `respond.sh`, `prom-scrape.sh` et `engagement-adapter.sh` parlaient au même
    `PLUME_CENTRAL`, avec le même jeton, en `http://` distant sans un mot. `respond.sh` y lisait des actions
    qu'il EXÉCUTE EN ROOT (cscli, fail2ban, nft) : un intermédiaire pouvait répondre à la place du central
    et faire bannir l'adresse de son choix ; `engagement-adapter.sh` y lisait des exemptions de ban.
(g) `kube-audit.sh` posait `src_ip` sans `json_escape` : le motif `[^"]+` garde un antislash, un `\"` du
    journal laissait un antislash final qui rendait l'enveloppe ENTIÈRE illisible.

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
    illisible) REFUSÉ — code 2, `REFUS` sur stderr, curl jamais appelé, spool intact même
    au-dessus du plafond, mot de passe de l'URL jamais imprimé ; opt-in `PLUME_SHIP_ALLOW_PLAINTEXT=1`
    expédie avec un avertissement, et le succès ne nomme le central que par schéma et hôte (ni en
    clair, ni en `https://`) ; boucle locale (127.0.0.1, ::1, localhost, LOCALHOST, identité devant
    127.0.0.1) et `https://` expédient sans un mot ; un lien symbolique n'est ni expédié ni supprimé,
    un répertoire est ignoré (jamais passé à `--data-binary`, passage en code 0), un nom à espace part, un spool dont le CHEMIN porte un espace est
    expédié et évincé entier ; l'éviction ne supprime rien hors du spool, n'évince ni un lien, ni une
    FIFO nommée en `.json`, ni un fichier hors motif, et l'aveu porte le compte RÉEL (pas le surplus prévu) ;
  · transport des trois autres (`P10.33-a`) : le MÊME corpus d'URL refusées que `ship.sh` est joué sur
    `respond.sh`, `prom-scrape.sh` et `engagement-adapter.sh` (bash) contre un faux central qui journalise
    chaque appel et un faux `nft` qui journalise chaque geste : code 2, `REFUS` sur stderr, AUCUN appel
    au central (le jeton ne part pas), mot de passe de l'URL jamais imprimé ; `respond.sh` n'exécute RIEN, et
    un verdict RETENU d'un tour précédent n'est pas rejoué (la porte passe avant le rejeu, qui appelle le
    central avant la liste) et reste intact — sous un transport admis, ce même verdict est rejoué et remis ;
    `engagement-adapter.sh` révoque l'exemption tenue d'un cycle précédent (REVERT-ALL, là où un échec
    ordinaire la garderait en HOLD). Boucle locale (le corpus de `ship.sh`) et `https://` avec identité :
    le central est appelé, l'action servie EST exécutée, le cycle réconcilie, sans un mot ; opt-in
    `PLUME_SHIP_ALLOW_PLAINTEXT=1` -> admis avec avertissement, une autre valeur -> refus. `prom-scrape.sh` :
    défaut (central absent) = boucle locale admise ; aucune cible scrapée ne reçoit `-K` (le jeton ne part
    que vers le central), une cible et le central ne s'impriment que par schéma et hôte — cible vide, cible
    injoignable et remise non-200 (503) comprises, chacune porteuse d'une identité dans son URL ;
    `engagement-adapter.sh revert-expired` sous un central REFUSÉ révoque l'exemption échue (faux nft :
    `delete rule … handle 42`), code 0, sans juger ni appeler le central ;
  · kube-audit : `sourceIPs` porteur d'un `\"` ou de deux antislashs -> enveloppe lisible en JSON STRICT,
    `src_ip` décodée égale à la valeur extraite ;
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
· LA PORTE DU TRANSPORT EXISTE EN TROIS TEXTES : `lib.sh` (`ship.sh`, `prom-scrape.sh`) et une copie dans
  chacun des deux enforcers, qui ne sourcent pas `lib.sh`. Leur égalité est tenue par le corpus commun
  joué ici, pas par un texte unique : une forme d'URL absente du corpus peut les faire diverger.
· Les CIBLES `/metrics` de `prom-scrape.sh` ne sont pas soumises à la porte : aucun jeton ne leur part
  (jugé), mais une cible déclarée en `http://` est lue en clair — un tiers sur le chemin peut lire ou
  FALSIFIER la mesure entrante. Choix assumé (un exporteur se sert en `http://`), non jugé ici.
· Le collecteur Windows (`collectors/windows/plume-collector.ps1`) porte la même porte (`P10.33-i`),
  écrite en PowerShell : elle n'est pas jouée ici mais par `check_windows_collector_is_honest.py`,
  qui exécute le collecteur sous `pwsh` sur son propre corpus d'URL.
· Les autres capteurs qui posent `src_ip` brut le tirent d'un motif borné (`SRC=[0-9A-Fa-f.:]*` de
  ufw, portscan, origin-drop ; `[0-9.]*` d'auditd ; adresses de conntrack) : non joués ici.
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
          "touch", "test", "[", "find", "xargs", "stat", "sha256sum", "jq", "true", "false", "od", "dd"]
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

    def jouer(self, script, env_plus=None, cwd=None, interp=None, args=()):
        env = {"PATH": self.bin, "FAKE_DIR": self.fake, "PLUME_SPOOL": self.spool, "PLUME_STATE": self.etat,
               "PLUME_LIB": LIB, "LC_ALL": "C.UTF-8", "HOME": self.d}
        env.update(env_plus or {})
        return subprocess.run([interp or SH, os.path.join(COL, script), *args], env=env, capture_output=True, text=True,
                              timeout=120, cwd=cwd or self.d, stdin=subprocess.DEVNULL)

    def outil(self, nom, texte):
        p = os.path.join(self.bin, nom)
        with open(p, "w") as f:
            f.write(texte)
        os.chmod(p, stat.S_IRWXU)


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
# LE CORPUS D'URL DU TRANSPORT, UN SEUL : il est joué sur `ship.sh` ET sur les trois autres scripts qui
# parlent au central (`P10.33-a`). Deux copies de la porte vivent dans les enforcers (qui ne sourcent pas
# lib.sh) : c'est ce corpus commun, et non un commentaire, qui tient l'égalité de leurs verdicts.
URLS_REFUSEES = (
    "http://central.invalid:7000", "http://u:motdepasse-de-garde@192.0.2.10:7000/",
    "central.invalid:7000", "HTTP://192.0.2.10", "http://127.0.0.1.evil.invalid/",
    "http://localhost@192.0.2.10/", "http://127.0.0.1x/", "http://127.0.0.1.2/",
    "ftp://192.0.2.10/",
    # l'autorite s'arrete au premier `/`, `?` ou `#` : un `@` APRES n'est pas une identite
    # (curl vise `evil.invalid`, mesure) ; chaque URL retire l'une des trois coupures.
    "http://evil.invalid/@127.0.0.1:7000", "http://evil.invalid?@127.0.0.1/",
    "http://evil.invalid#@127.0.0.1/",
    "http://127..0.1/", "http://127.0.0./", "x:motdepasse-de-garde@h/a://b")
URLS_BOUCLE_LOCALE = ("http://127.0.0.1:7000", "http://localhost:7000", "http://[::1]:7000", "http://127.1.2.3:7000",
                      "http://u@127.0.0.1:7000", "http://LOCALHOST:7000")


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
    for url in URLS_REFUSEES:
        scen = f"ship-refus[{url}]"
        bac = bac_ship(base)
        for i in range(3):
            p = os.path.join(bac.spool, f"e{i}.json")
            open(p, "w").write("{}")
            os.utime(p, (time.time() - 100 + i,) * 2)
        r = bac.jouer("ship.sh", dict(env_base, PLUME_CENTRAL=url, PLUME_SPOOL_MAX_FILES="1"))
        if r.returncode != 2:
            # le code 2 est le contrat écrit (README, ARCHITECTURE) : un superviseur le distingue d'un échec ordinaire
            faute(scen, f"code {r.returncode} au lieu de 2 : le refus du clair distant n'a pas son code")
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
    if r.returncode != 2 or appels_curl(bac):
        faute("ship-opt-in-flou", f"une valeur d'opt-in autre que 1 ouvre le clair (ou le refus n'a pas son code 2) : "
                                  f"rc={r.returncode} curl={appels_curl(bac)}")

    # boucle locale : inchangé
    for url in URLS_BOUCLE_LOCALE:
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


# --- (f) le transport des trois autres scripts qui parlent au central (`P10.33-a`) ----------------------
# Un faux central : il journalise CHAQUE appel (URL, présence de `-K`, ce que `-K -` a reçu), sert une
# action de ban sur `/api/actions/pending`, une liste vide d'engagements, accepte les métriques et les
# verdicts ; toute autre URL est une CIBLE scrapée (`/vide` rend un corps vide, `/injoignable` échoue
# comme une connexion refusée). `$FAKE_DIR/code-prom`, s'il existe, est le code rendu aux métriques.
CURL_CENTRAL = r"""#!/bin/sh
k=0; url=""; sortie=""; prec=""
for a; do
  [ "$prec" = "-o" ] && sortie=$a
  [ "$prec" = "-K" ] && k=1
  prec=$a; url=$a
done
entree=""; [ "$k" = 1 ] && entree=$(cat)
printf '%s\t%s\n' "$k" "$url" >> "$FAKE_DIR/curl.appels"
printf '%s\n' "$url" >> "$FAKE_DIR/curl.urls"
[ "$k" = 1 ] && printf '%s\n' "$entree" >> "$FAKE_DIR/curl.k"
ecrire() { if [ -n "$sortie" ]; then printf '%s' "$1" > "$sortie"; else printf '%s' "$1"; fi; }
case "$url" in
  */api/actions/pending*) printf '7\tban_ip\t203.0.113.7\t0\n' ;;
  */api/actions/result) ecrire '{"ok":true}'; printf 200 ;;
  */api/engagements/active) ecrire '[]'; printf 200 ;;
  */api/metrics/prom*) if [ -f "$FAKE_DIR/code-prom" ]; then cat "$FAKE_DIR/code-prom"; else printf 200; fi ;;
  */vide) : ;;
  */injoignable) exit 7 ;;
  *) printf 'mesure_de_garde 1\n' ;;
esac
"""
# Faux enforcement : CHAQUE appel est journalisé ; rien n'est appliqué nulle part.
NFT_JOURNAL = r"""#!/bin/sh
printf 'nft %s\n' "$*" >> "$FAKE_DIR/enforcement"
exit 0
"""
CIBLES_PROM = "http://u:motdepasse-de-garde@198.51.100.20:9100/metrics http://u:motdepasse-de-garde@198.51.100.21/vide"


def bac_central(base):
    bac = Bac(base, None)
    bac.outil("curl", CURL_CENTRAL)
    bac.outil("nft", NFT_JOURNAL)
    vide = os.path.join(bac.d, "liste-d-epargne-vide")
    open(vide, "w").close()
    return bac, vide


def appels_central(bac):
    p = os.path.join(bac.fake, "curl.appels")
    return [tuple(l.split("\t", 1)) for l in open(p).read().splitlines()] if os.path.exists(p) else []


def enforcement(bac):
    p = os.path.join(bac.fake, "enforcement")
    return open(p).read() if os.path.exists(p) else ""


# Faux nft du dead-man : il journalise chaque geste et, à `-a list chain`, rend UNE règle de l'adaptateur
# (handle 42) pour l'exemption tenue ; `delete rule … handle 42` est la révocation attendue.
NFT_DEADMAN = r"""#!/bin/sh
printf 'nft %s\n' "$*" >> "$FAKE_DIR/enforcement"
case "$*" in
  *"list chain"*) printf '\t\tip saddr 198.51.100.0/24 accept comment "plume-engagement:eng-de-garde|198.51.100.0/24" # handle 42\n' ;;
esac
exit 0
"""
CIBLES_PROM_ECHEC = ("http://u:motdepasse-de-garde@198.51.100.22:9100/injoignable "
                     "http://u:motdepasse-de-garde@198.51.100.20:9100/metrics")


# Un verdict que `respond.sh` n'a pas pu remettre à un tour précédent (format de `retenir_pour_rejeu` :
# `<id> TAB <tours> TAB <corps>`). L'id 9 n'est pas celui de l'action servie (7) : le ban reste exécuté.
VERDICT_RETENU = '9\t0\t{"id":9,"status":"done","result":"ban pose au tour precedent"}\n'


def chemin_verdicts_retenus(bac):
    return os.path.join(bac.etat, "responder", "verdicts-a-remettre")


def poser_verdict_retenu(bac):
    os.makedirs(os.path.dirname(chemin_verdicts_retenus(bac)), mode=0o700, exist_ok=True)
    with open(chemin_verdicts_retenus(bac), "w") as f:
        f.write(VERDICT_RETENU)


def lire_verdicts_retenus(bac):
    p = chemin_verdicts_retenus(bac)
    return open(p).read() if os.path.exists(p) else None


def exiger_rejeu_joue(scen, bac, r):
    """Validité de l'épreuve du refus : sous un transport admis, le verdict posé EST rejoué et remis (le
    script lit bien ce fichier, à ce chemin, sous cette forme) — sans quoi « zéro appel au refus » ne
    prouverait rien sur l'ordre porte -> rejeu. Jugé seulement si la porte a laissé passer (la liste est
    demandée) : un transport admis à tort refusé est la faute de `juger_admis`, pas un instrument muet."""
    if not any("/api/actions/pending" in u for _, u in appels_central(bac)):
        return
    if "#9 verdict REJOUE et remis" not in r.stderr or (lire_verdicts_retenus(bac) or "").strip():
        refus(f"[{scen}] le verdict retenu posé n'est pas rejoué sous un transport admis : l'épreuve du refus "
              f"avec verdict retenu ne mesure rien ({r.stderr[:300]!r}, file={lire_verdicts_retenus(bac)!r})")
    if not any(u.endswith("/api/actions/result") for _, u in appels_central(bac)):
        refus(f"[{scen}] aucune remise vers /api/actions/result : le faux central ne voit pas le rejeu")


def jouer_capteur_central(bac, nom, vide, url, plus=None):
    env = {"PLUME_TOKEN": "jeton-de-garde", "PLUME_HOST_LABEL": "hote-de-garde"}
    if url is not None:
        env["PLUME_CENTRAL"] = url
    if nom == "respond.sh":
        env.update(PLUME_RESPONDER="1", PLUME_RESPONDER_APPLY="1", PLUME_RESPONDER_ALLOW=vide, PLUME_BAN_BACKEND="nft")
    elif nom == "engagement-adapter.sh":
        env.update(PLUME_ENGAGEMENT_ADAPTER="1")
    elif nom == "prom-scrape.sh":
        env.update(PLUME_PROM_TARGETS=CIBLES_PROM)
    env.update(plus or {})
    return bac.jouer(nom, env, interp=BASH if nom == "engagement-adapter.sh" else None)


def chemin_central(nom):
    return {"respond.sh": "/api/actions/pending?host=hote-de-garde", "engagement-adapter.sh": "/api/engagements/active",
            "prom-scrape.sh": "/api/metrics/prom?host=hote-de-garde"}[nom]


def juger_admis(scen, bac, nom, r, url, mot_attendu):
    """Le transport est admis : le central est appelé, le travail est fait, et le mot attendu (aucun, ou
    l'avertissement de l'opt-in) est seul sur stderr."""
    urls = [u for _, u in appels_central(bac)]
    if not urls:
        # Un transport ADMIS doit appeler le central : son silence est la faute jugée ici (le faux central
        # lui-même est validé par les autres jugements de ce scénario, qui exigent ses réponses).
        faute(scen, f"le central n'est jamais appelé alors que le transport est admis : {r.stderr[:300]!r}")
        return
    if r.returncode != 0:
        faute(scen, f"rc={r.returncode} : {r.stderr[:300]!r}")
    if "REFUS" in r.stderr:
        faute(scen, f"refus alors que le transport est admis : {r.stderr[:300]!r}")
    if mot_attendu is None and "AVERTISSEMENT" in r.stderr:
        faute(scen, f"avertissement sans opt-in : {r.stderr[:300]!r}")
    if mot_attendu and mot_attendu not in r.stderr:
        faute(scen, f"l'opt-in passe sans {mot_attendu!r} : {r.stderr[:300]!r}")
    if url is not None and (url.rstrip("/") + chemin_central(nom)) not in urls:
        faute(scen, f"le central n'est pas appelé à {url + chemin_central(nom)!r} : {urls!r}")
    if nom == "respond.sh" and "add element inet plume blocklist { 203.0.113.7 }" not in enforcement(bac):
        faute(scen, f"l'action servie n'est pas exécutée (instrument muet ?) : {enforcement(bac)!r} {r.stderr[:300]!r}")
    if nom == "engagement-adapter.sh" and "mode=reconcile" not in r.stderr:
        faute(scen, f"le cycle ne réconcilie pas : {r.stderr[-300:]!r}")
    if nom == "prom-scrape.sh":
        juger_cibles_prom(scen, bac, r)


def juger_cibles_prom(scen, bac, r):
    """Aucune cible scrapée ne reçoit le jeton, et une cible ne s'imprime que par schéma et hôte."""
    cibles = [(k, u) for k, u in appels_central(bac) if "/api/" not in u]
    if sorted(u for _, u in cibles) != sorted(CIBLES_PROM.split()):
        faute(scen, f"cibles scrapées {cibles!r} au lieu de {CIBLES_PROM.split()!r}")
    if any(k != "0" for k, _ in cibles):
        faute(scen, f"une cible scrapée reçoit une configuration `-K` (le jeton part vers elle) : {cibles!r}")
    if "motdepasse-de-garde" in r.stdout + r.stderr:
        faute(scen, f"l'identité d'une cible est imprimée : {(r.stdout + r.stderr)[:300]!r}")
    if "http://198.51.100.21 vide" not in r.stderr:
        faute(scen, f"la cible vide n'est pas nommée par schéma et hôte : {r.stderr[:300]!r}")
    pk = os.path.join(bac.fake, "curl.k")
    if not os.path.exists(pk) or "jeton-de-garde" not in open(pk).read():
        refus(f"[{scen}] le jeton n'arrive pas au faux central par `-K -` : l'épreuve des cibles ne mesure rien")


def scen_transport_des_autres(base):
    for nom in ("respond.sh", "prom-scrape.sh", "engagement-adapter.sh"):
        for url in URLS_REFUSEES:
            scen = f"{nom}-refus[{url}]"
            bac, vide = bac_central(base)
            if nom == "engagement-adapter.sh":
                # une exemption tenue d'un cycle précédent : un HOLD la garderait, le refus la révoque
                with open(os.path.join(bac.etat, "engagement-adapter.applied"), "w") as f:
                    f.write("198.51.100.0/24\teng-de-garde\t%d\n" % (int(time.time()) + 3600))
            if nom == "respond.sh":
                # un verdict RETENU d'un tour précédent : son rejeu appelle le central AVANT la liste, donc la
                # porte doit passer avant LUI aussi (sinon le jeton part en clair vers /api/actions/result)
                poser_verdict_retenu(bac)
            r = jouer_capteur_central(bac, nom, vide, url)
            if r.returncode != 2:
                faute(scen, f"code {r.returncode} au lieu de 2 : le clair vers un hôte distant n'est pas refusé par son code")
            if "REFUS" not in r.stderr:
                faute(scen, f"aucun refus nommé sur stderr : {r.stderr[:300]!r}")
            if "motdepasse-de-garde" in r.stderr + r.stdout:
                faute(scen, "le mot de passe d'une URL est imprimé")
            if appels_central(bac):
                faute(scen, f"curl appelé malgré le refus (jeton et requête partis) : {appels_central(bac)}")
            # (l'adaptateur, lui, DOIT agir sur refus : il révoque — jugé par son état ci-dessous)
            if nom != "engagement-adapter.sh" and enforcement(bac):
                faute(scen, f"un geste d'enforcement est parti malgré le refus : {enforcement(bac)!r}")
            if nom == "respond.sh" and lire_verdicts_retenus(bac) != VERDICT_RETENU:
                faute(scen, f"le verdict retenu n'est plus intact après le refus : {lire_verdicts_retenus(bac)!r}")
            if nom == "engagement-adapter.sh":
                tenu = open(os.path.join(bac.etat, "engagement-adapter.applied")).read()
                if tenu.strip() or "mode=revert-all" not in r.stderr:
                    faute(scen, f"le refus ne révoque pas l'exemption tenue (REVERT-ALL attendu) : état={tenu!r} "
                                f"{r.stderr[-300:]!r}")
        for url in URLS_BOUCLE_LOCALE + ("https://u:motdepasse-de-garde@central.invalid:7000",):
            scen = f"{nom}-admis[{url}]"
            bac, vide = bac_central(base)
            if nom == "respond.sh":
                poser_verdict_retenu(bac)
            r = jouer_capteur_central(bac, nom, vide, url)
            if nom == "respond.sh":
                exiger_rejeu_joue(scen, bac, r)
            schema, _, autorite = url.partition("://")
            att = f"{schema}://{autorite.split('/', 1)[0].rsplit('@', 1)[-1]}"   # schéma://hôte[:port], sans identité
            juger_admis(scen, bac, nom, r, url if "@" not in url else None, None)
            if "@" in url and not any(u.startswith(url) for _, u in appels_central(bac)):
                faute(scen, f"le central n'est pas appelé à {url!r} : {appels_central(bac)!r}")
            if nom == "prom-scrape.sh" and not r.stdout.rstrip("\n").endswith(f"-> {att}"):
                faute(scen, f"le succès ne nomme pas le central par schéma et hôte ({att}) : {r.stdout[:200]!r}")
        scen = f"{nom}-opt-in"
        bac, vide = bac_central(base)
        r = jouer_capteur_central(bac, nom, vide, "http://192.0.2.10:7000", {"PLUME_SHIP_ALLOW_PLAINTEXT": "1"})
        juger_admis(scen, bac, nom, r, "http://192.0.2.10:7000", "AVERTISSEMENT")
        scen = f"{nom}-opt-in-flou"
        bac, vide = bac_central(base)
        r = jouer_capteur_central(bac, nom, vide, "http://192.0.2.10:7000", {"PLUME_SHIP_ALLOW_PLAINTEXT": "oui"})
        if r.returncode != 2 or appels_central(bac) or (nom == "respond.sh" and enforcement(bac)):
            faute(scen, f"une valeur d'opt-in autre que 1 ouvre le clair (ou le refus n'a pas son code 2) : "
                        f"rc={r.returncode} {appels_central(bac)!r}")
    # le défaut de prom-scrape (central absent) est la boucle locale : il scrape et expédie sans un mot
    scen = "prom-scrape.sh-defaut"
    bac, vide = bac_central(base)
    r = jouer_capteur_central(bac, "prom-scrape.sh", vide, None)
    juger_admis(scen, bac, "prom-scrape.sh", r, "http://127.0.0.1:7000", None)
    scen_prom_echecs(base)
    scen_dead_man_hors_transport(base)


def scen_prom_echecs(base):
    """Les deux autres messages qui nomment une cible — injoignable, et remise refusée par le central —
    ne l'impriment, eux aussi, que par schéma et hôte (l'identité de l'URL ne sort pas)."""
    scen = "prom-scrape.sh-echecs"
    bac, vide = bac_central(base)
    with open(os.path.join(bac.fake, "code-prom"), "w") as f:
        f.write("503")
    r = jouer_capteur_central(bac, "prom-scrape.sh", vide, "https://central.invalid:7000",
                              {"PLUME_PROM_TARGETS": CIBLES_PROM_ECHEC})
    urls = [u for _, u in appels_central(bac)]
    if sorted(u for u in urls if "/api/" not in u) != sorted(CIBLES_PROM_ECHEC.split()):
        refus(f"[{scen}] les deux cibles ne sont pas scrapées : {urls!r}")
    if "https://central.invalid:7000/api/metrics/prom?host=hote-de-garde" not in urls:
        refus(f"[{scen}] la remise au central n'est pas tentée : la branche non-200 n'est pas jouée {urls!r}")
    if "motdepasse-de-garde" in r.stdout + r.stderr:
        faute(scen, f"l'identité d'une cible en échec est imprimée : {(r.stdout + r.stderr)[:400]!r}")
    for attendu in ("prom-scrape: http://198.51.100.22:9100 injoignable",
                    "prom-scrape: http://198.51.100.20:9100 -> HTTP 503"):
        if attendu not in r.stderr:
            faute(scen, f"{attendu!r} absent (cible non nommée par schéma et hôte) : {r.stderr[:400]!r}")
    if "prom-scrape: 0/2 cible(s)" not in r.stdout:
        faute(scen, f"le bilan ne compte pas deux échecs sur deux : {r.stdout[:200]!r}")


def scen_dead_man_hors_transport(base):
    """`engagement-adapter.sh revert-expired` partage le fichier d'environnement du cycle : un central
    refusé ne doit PAS l'empêcher de révoquer une exemption échue (aucun réseau, code 0)."""
    scen = "engagement-adapter.sh-revert-expired[central refusé]"
    bac, vide = bac_central(base)
    bac.outil("nft", NFT_DEADMAN)
    with open(os.path.join(bac.etat, "engagement-adapter.applied"), "w") as f:
        f.write("198.51.100.0/24\teng-de-garde\t%d\n" % (int(time.time()) - 60))
    env = {"PLUME_TOKEN": "jeton-de-garde", "PLUME_HOST_LABEL": "hote-de-garde", "PLUME_ENGAGEMENT_ADAPTER": "1",
           "PLUME_CENTRAL": "http://u:motdepasse-de-garde@192.0.2.10:7000"}
    r = bac.jouer("engagement-adapter.sh", env, interp=BASH, args=("revert-expired",))
    geste = enforcement(bac)
    # Pas de refus de conclure ici : un dead-man qui n'interroge plus nft NE RÉVOQUE PAS, c'est la faute
    # jugée ; le faux nft est validé par le cas nominal (sa règle handle 42 doit être supprimée).
    if r.returncode != 0:
        faute(scen, f"rc={r.returncode} : le refus du transport bloque le dead-man {r.stderr[-300:]!r}")
    if "delete rule inet plume-origin-fw prerouting handle 42" not in geste:
        faute(scen, f"l'exemption échue n'est pas révoquée : {geste!r} {r.stderr[-300:]!r}")
    if "REFUS" in r.stderr or appels_central(bac):
        faute(scen, f"le dead-man juge ou appelle le central : {appels_central(bac)!r} {r.stderr[-300:]!r}")
    if "motdepasse-de-garde" in r.stdout + r.stderr:
        faute(scen, "le mot de passe de l'URL est imprimé")


# --- (g) kube-audit : l'adresse source passe par l'échappement --------------------------------------------
def scen_kube_audit(base):
    scen = "kube-audit-src_ip"
    bac = Bac(base, None)
    journal = os.path.join(bac.d, "audit.log")
    # `[^"]+` après `"sourceIPs":["` s'arrête au guillemet mais GARDE l'antislash : la valeur extraite du
    # premier est `198.51.100.7\` (antislash final), du second `a\\b` (deux antislashs bruts).
    hostiles = ['198.51.100.7\\', 'a\\\\b']
    lignes = []
    for i, brut in enumerate(('198.51.100.7\\"x', 'a\\\\b')):
        lignes.append('{"stage":"ResponseComplete","verb":"get","user":{"username":"u%d"},"sourceIPs":["%s"],'
                      '"objectRef":{"resource":"pods"},"responseStatus":{"metadata":{},"code":200}}' % (i, brut))
    with open(journal, "w") as f:
        f.write("\n".join(lignes) + "\n")
    r = bac.jouer("kube-audit.sh", {"PLUME_KUBE_AUDIT_LOG": journal})
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    ips = sorted(e.get("src_ip", "") for e in evs if e.get("source") == "kube-audit")
    if not evs and not enveloppes(bac.spool):
        refus(f"[{scen}] aucune enveloppe publiée : l'épreuve ne mesure rien ({r.stderr[:300]!r})")
    if ips != sorted(hostiles):
        faute(scen, f"src_ip {ips!r} au lieu de {sorted(hostiles)!r}")


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
    global SH, BASH
    SH = shutil.which("dash") or shutil.which("sh")
    if not SH:
        refus("aucun `sh`")
    BASH = shutil.which("bash")
    if not BASH:
        refus("aucun `bash` (engagement-adapter.sh en exige un)")
    if not shutil.which("jq"):
        refus("aucun `jq` (bans/CrowdSec le requiert)")
    for s in ("clamav.sh", "yara.sh", "vuln.sh", "imgdrift.sh", "bans.sh", "crowdsec.sh", "ship.sh", "lib.sh",
              "respond.sh", "prom-scrape.sh", "engagement-adapter.sh", "kube-audit.sh", "minio-audit-relay.py"):
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
        scen_transport_des_autres(base)
        scen_kube_audit(base)
        scen_relais(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if fautes:
        for f in fautes:
            print(f"::error::{NOM} : {f}")
        print(f"{len(fautes)} faute(s).")
        return 1
    print(f"collecte sûre : JSON échappé sous {', '.join(t for t, _ in awks)} (clamav, yara, vuln, imgdrift, bans, crowdsec), "
          "aveu sans backend, clair distant refusé (ship, respond, prom-scrape, engagement-adapter), src_ip de "
          "kube-audit échappée, parcours du spool sûr, relais fermé sans jeton.")
    return 0


SH = None
BASH = None

if __name__ == "__main__":
    sys.exit(main())
