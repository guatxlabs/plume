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
(d') `ship.sh` jugeait un nom du spool (`[ -f ] && [ ! -L ]`) puis curl ouvrait ce NOM un instant plus
    tard. Le spool est 2770 root:soc (le relais MinIO y écrit sous `User=soc`) et `ship.sh` tourne en
    root : un membre de `soc` qui remplaçait le nom par un lien dans cette fenêtre faisait poster au
    central, en root, n'importe quel fichier de l'hôte. Rejoué avec un faux curl qui substitue au
    démarrage : le secret partait. Le fichier est désormais renommé dans `$STATE/envoi/` (privé) et
    jugé là (`find -type f -links 1`) ; un objet substitué est mis à l'écart, compté, avoué.
(e) `minio-audit-relay.py` avec un jeton vide, absent ou illisible était OUVERT (un avertissement), et
    comparait le jeton par `!=`.
(f) `P10.33-a` — `respond.sh`, `prom-scrape.sh` et `engagement-adapter.sh` parlaient au même
    `PLUME_CENTRAL`, avec le même jeton, en `http://` distant sans un mot. `respond.sh` y lisait des actions
    qu'il EXÉCUTE EN ROOT (cscli, fail2ban, nft) : un intermédiaire pouvait répondre à la place du central
    et faire bannir l'adresse de son choix ; `engagement-adapter.sh` y lisait des exemptions de ban.
(g) `kube-audit.sh` posait `src_ip` sans `json_escape` : le motif `[^"]+` garde un antislash, un `\"` du
    journal laissait un antislash final qui rendait l'enveloppe ENTIÈRE illisible.
(h) `respond.sh` (remise du verdict, deux envois) passait son corps en `--data-binary "$1"`,
    `cloudflare.sh` et `cloudflare-http.sh` en `--data "$body"`. curl lit un tel argument qui COMMENCE par
    « @ » comme un FICHIER LOCAL et en envoie le contenu (`respond.sh` tourne en root). Ces corps commencent
    dans la forme livrée par « { » : piège latent, rendu non-écrivable. Les quatre passent en `--data-raw`.

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
  · bans avec un fail2ban lisible ET un cscli sans jq : battement SANS `active_bans`, aveu de lecture
    partielle qui nomme CrowdSec, ban fail2ban publié ;
  · ship, substitution : (1) un faux curl remplace `$SPOOL/<nom posté>` par un lien vers un secret à
    l'instant où il démarre, puis lit le chemin reçu en suivant les liens — le secret ne doit jamais
    partir, le vrai corps si ; (2) un faux `mv` remplace le nom par un lien, un lien dur ou un tube juste
    avant sa mise à l'abri — rien n'est lu, l'objet est dans `refuses/`, un aveu `spool-substitue` porte
    le compte 1, le second fichier (sain) part ; un fichier laissé dans l'abri est repris, un réessai
    rend le fichier au spool, un LIEN laissé dans l'abri n'est ni lu ni rendu ni `chmod` (mode de sa
    cible inchangé), un `PLUME_STATE` impossible à créer donne code 2 sans appel ; un nom seulement
    SUPPRIMÉ avant sa mise à l'abri n'est pas avoué comme substitué ; un VRAI répertoire posé au nom
    libéré pendant l'envoi ne reçoit rien, le fichier reste dans l'abri, l'échec est dit, le passage
    suivant le reprend ; spool et abri sur deux volumes (faux `stat`) avec `fs.protected_hardlinks`
    autre que 1 (`PLUME_PROC_ROOT`) : ATTENTION dite, et muette sur un seul volume ou avec le sysctl à 1 ;
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
    un répertoire est ignoré (jamais passé à `--data-binary`, passage en code 0), un nom à espace part ; deux liens laissés
    dans l'abri, dont un pendant, sont écartés et avoués avec le compte 2, l'abri trouvé en 0755 est
    ramené à 0700, une remise au spool ne suit pas un lien posé vers un répertoire, un refus permanent
    non écartable revient au spool, et `systemd/plume-ship.service` déclare l'état inscriptible ; un spool dont le CHEMIN porte un espace est
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
  · vuln (`P10.32-p`) : `fields` de chaque événement est égal, ENSEMBLE EXACT, à ce que dit la ligne du
    scanner — `agent_name` (l'hôte de l'enveloppe), `cve`, `vuln_package`, `vuln_package_version`,
    `vuln_severity` (minuscules, vocabulaire Wazuh), `image`, plus `vuln_fixed` et `vuln_cvss` quand le
    scanner les donne —, `message` garde sa forme livrée ; une seconde ligne porte une valeur hostile dans
    l'identifiant, la sévérité et le score (les trois colonnes que la première laisse saines) : enveloppe
    STRICTE, valeurs décodées telles quelles. Le TEMPLATE de `vuln.sh` est joué par le VRAI moteur
    (`trivy convert` sur un rapport fabriqué) quand un trivy réel est présent ;
  · kube-audit : `sourceIPs` porteur d'un `\"` ou de deux antislashs -> enveloppe lisible en JSON STRICT,
    `src_ip` décodée égale à la valeur extraite ;
  · relais : jeton absent, vide, blanc, illisible (un répertoire) ou non UTF-8 -> refus de démarrer,
    code non nul, message nommé et non une trace d'exception ; jeton posé -> GET 200, POST sans jeton ou faux 401, POST juste 200 et événement au
    spool, jeton devenu vide en cours de route -> 503 ; jeton NON ASCII sous `LC_ALL=C`,
    `PYTHONCOERCECLOCALE=0`, `-X utf8=0` -> démarre et l'accepte (lecture en UTF-8 fixe). Puis, chargé en processus, la comparaison
    passe par `hmac.compare_digest` (espion posé sur le module : un `!=` ne l'appelle pas), et
    `autorisation_acceptee(…, "")` rend False en appel direct.

  · corps en ligne : dans `collectors/**/*.sh`, toute invocation de curl est découpée en mots
    (commentaires, suites de ligne, `$(…)` entre guillemets compris) ; un `-d` (grappe courte comprise),
    `--data`, `--data-ascii`, `--data-binary`, `--data-urlencode` ou `--json` est une FAUTE, sauf la forme
    `@"$<variable>"` dans un script de `ENVOI_DE_FICHIER_ADMIS` — DEUX entrées, À DESSEIN : `ship.sh`
    (lot du spool) et `prom-scrape.sh` (son propre `mktemp`), où le fichier est choisi par le script ;
    une exception qui ne sert plus est une faute. Puis les quatre envois LIVRÉS (extraits du script :
    `remettre_une_fois` avec et sans `mktemp`, la requête des deux capteurs Cloudflare) sont joués avec un
    corps « @<fichier témoin> » sous un faux curl FIDÈLE (il lit le fichier comme le vrai) : le fichier
    n'est jamais lu, l'argument part tel quel.

L'INSTRUMENT SE VALIDE AVANT DE CONCLURE
----------------------------------------
Sans `sh`, sans `jq`, sans awk exercé, ou si un script est introuvable, la garde REFUSE DE CONCLURE
(code 2). Chaque scénario vérifie que son faux outil a bien été appelé : un bouchon muet ferait
passer un capteur aveugle pour un capteur sûr.

CE QU'ELLE NE TIENT PAS
-----------------------
· Les modes k3s des capteurs (`k3s kubectl`) ne sont pas joués : seul `kubectl` l'est, la commande
  est la même.
· La substitution est rejouée par des outils truqués qui frappent à un instant FIXÉ, pas par un vrai
  concours de vitesse. Le refus d'un LIEN DUR ne tient que si spool et état sont sur le MÊME volume
  (les installeurs les posent tous deux sous /var/lib/plume) : entre deux volumes, `mv` recopie, et un
  lien dur posé dans le spool devient dans l'abri un fichier à un seul lien, qui est EXPÉDIÉ. La portée
  est alors bornée par `fs.protected_hardlinks` (un membre de `soc` ne lie qu'un fichier qu'il possède
  ou peut déjà lire et écrire), non par le script ; non joué ici (un second volume manque au bac).
  Un lien SYMBOLIQUE, lui, n'est jamais suivi dans ce cas (`mv` de coreutils recopie le lien lui-même).
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
· Le template trivy de `vuln.sh` n'est jugé QUE si un trivy réel est là (`PLUME_TRIVY_REEL` ou PATH) ; sans
  lui, la sortie de la garde le dit « NON JOUÉ » — la CI n'installe pas trivy. Le faux `trivy` des bacs
  ignore `--template`.
· `agent_name` de `vuln.sh` est l'hôte lu dans `/proc` : non injectable dans le bac, son échappement n'est
  pas éprouvé (l'enveloppe de `lib.sh` pose d'ailleurs `host` sans échappement). Une version installée VIDE
  devient `-` dans `vuln_package_version` (le filtre awk bouche les colonnes vides, sans quoi `read` les
  fondrait) : forme non jugée.
· `crowdsec.sh` n'est joué que pour ses alertes : santé, hub et acquisition ne le sont pas ici.
· Le temps constant de la comparaison n'est pas MESURÉ (un chronomètre frapperait dans les deux
  sens) : la garde exige l'appel de la primitive à temps constant.

· Corps en ligne : aucun corps livré ne commence par « @ » (`post_result` et le rejeu exigent
  `{"id":`, les corps Cloudflare sortent de `jq -n`) : le témoin comportemental joue donc le TEXTE extrait
  de l'envoi avec un corps fabriqué, pas le capteur entier. Le découpage statique ne suit ni un `curl`
  appelé par une variable (`$CURL`) ni une configuration `-K` qui porterait un `data = @…`.

Sortie : 0 tenu · 1 au moins une propriété violée · 2 l'instrument REFUSE DE CONCLURE.
"""
import glob
import hashlib
import hmac as hmac_de_la_garde
import importlib.util
import json
import os
import re
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
    for f in fautes:   # une faute déjà jugée reste dite, même quand un autre scénario refuse de conclure
        print(f"::error::{NOM} : {f}")
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


# P10.32-p — les champs que `vuln.sh` pose dans `fields` : les MÊMES noms que le normaliseur Wazuh du démon
# (`daemon/src/ingest/endpoint.rs`, famille vulnerability-detector), que les panneaux semés « Vulnérabilités
# (CVE endpoint) » regroupent ; `vuln_fixed` et `image` sont propres au capteur. Ensemble EXACT, pas un compte.
VULN_CHAMPS_TOUJOURS = {"agent_name", "cve", "vuln_package", "vuln_package_version", "vuln_severity", "image"}
VULN_SEVERITES_WAZUH = {"critical", "high", "medium", "low"}


def scen_vuln(base, awk, tag):
    scen = f"vuln/{tag}"
    bac = Bac(base, awk, faux=("trivy",))
    # `vuln.sh` passe l image par `awk -v`, qui interprete les antislashs : l image porte le guillemet,
    # l antislash final est porte par le paquet (lu par `$0`, sans interpretation).
    img = "reg/img" + FORGE
    # Sortie FIDÈLE au template TSV de vuln.sh : sévérité, id, paquet, installée, corrigée (`-` si aucune),
    # CVSS v3 nvd (VIDE si trivy n'en a pas : la ligne finit alors par une tabulation). Valeurs piégées :
    # guillemet, antislash final, retour chariot (caractère de contrôle, invalide brut en JSON).
    ver_cr = "1.0\rx"
    lignes = [
        ("CRITICAL", "CVE-0001", FORGE, "1.0", "-", "9.8"),
        ("HIGH", "CVE-0002", ANTISLASH, GUILLEMET, ANTISLASH, ""),
        ("HIGH", "CVE-0003", GUILLEMET, ver_cr, "2.0", "7.5"),
    ]
    bac.poser("trivy.out", "".join("\t".join(l) + "\n" for l in lignes))
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
    lisibles = [env for _, env, _, _ in enveloppes(bac.spool) if env]
    if not lisibles:
        faute(scen, "aucune enveloppe lisible : les champs de vulnérabilité ne se jugent pas")
        return
    hotes = {env.get("host") for env in lisibles}
    if len(hotes) != 1 or not next(iter(hotes)):
        refus(f"[{scen}] l'enveloppe ne porte pas un hôte unique ({hotes}) : agent_name ne se juge pas")
    hote = next(iter(hotes))
    par_cve = {(e.get("fields") or {}).get("cve"): e for e in evs if e.get("source") == "vuln"}
    for sev, cve, pkg, inst, fixed, cvss in lignes:
        e = par_cve.get(cve)
        if e is None:
            faute(scen, f"{cve} : aucun événement ne porte fields.cve={cve!r} (champ absent ou renommé)")
            continue
        f = e.get("fields")
        if not isinstance(f, dict):
            faute(scen, f"{cve} : `fields` absent ou non objet : {e}")
            continue
        attendu = {"agent_name": hote, "cve": cve, "vuln_package": pkg,
                   # json_escape retire les caractères de contrôle (le \r) : c'est sa règle, la même partout.
                   "vuln_package_version": inst.replace("\r", ""), "vuln_severity": sev.lower(), "image": img}
        if fixed != "-":
            attendu["vuln_fixed"] = fixed
        if cvss:
            attendu["vuln_cvss"] = cvss
        if f != attendu:
            faute(scen, f"{cve} : fields {f!r} au lieu de {attendu!r}")
        if not VULN_CHAMPS_TOUJOURS <= set(f):
            faute(scen, f"{cve} : champs manquants {sorted(VULN_CHAMPS_TOUJOURS - set(f))}")
        if f.get("vuln_severity") not in VULN_SEVERITES_WAZUH:
            faute(scen, f"{cve} : vuln_severity={f.get('vuln_severity')!r} hors du vocabulaire Wazuh "
                        f"{sorted(VULN_SEVERITES_WAZUH)} (minuscules)")
        # `message` inchangé : la forme livrée avant P10.32-p.
        m = f"{cve} dans {pkg} {inst.replace(chr(13), '')} (corrige: {fixed}) image {img}"
        if e.get("message") != m:
            faute(scen, f"{cve} : message {e.get('message')!r} au lieu de {m!r}")


def scen_vuln_colonnes_hostiles(base, awk, tag):
    """Les trois colonnes que `scen_vuln` laisse saines — identifiant, sévérité, score — portent chacune une
    valeur hostile : sans `json_escape`, FORGE pose ses clés dans `fields`, l'antislash final et le guillemet
    rendent l'enveloppe illisible. Une sévérité hors vocabulaire rend `severity` 0 (`sevmap`) : c'est la
    forme livrée, jugée ici pour que la ligne ne disparaisse pas."""
    scen = f"vuln-colonnes/{tag}"
    bac = Bac(base, awk, faux=("trivy",))
    img = "reg/img2"
    sev, cve, cvss = ANTISLASH, FORGE, GUILLEMET
    bac.poser("trivy.out", "\t".join((sev, cve, "paq", "1.0", "2.0", cvss)) + "\n")
    r = bac.jouer("vuln.sh", {"PLUME_VULN_IMAGES": img})
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    lisibles = [env for _, env, _, _ in enveloppes(bac.spool) if env]
    vuln = [e for e in evs if e.get("source") == "vuln"]
    if len(vuln) != 1 or not lisibles:
        faute(scen, f"un événement vuln attendu, {len(vuln)} lu(s)")
        return
    e = vuln[0]
    attendu = {"agent_name": lisibles[0].get("host"), "cve": cve, "vuln_package": "paq",
               "vuln_package_version": "1.0", "vuln_severity": sev.lower(), "image": img,
               "vuln_fixed": "2.0", "vuln_cvss": cvss}
    if e.get("fields") != attendu:
        faute(scen, f"fields {e.get('fields')!r} au lieu de {attendu!r}")
    if e.get("severity") != 0 or e.get("category") != "vuln":
        faute(scen, f"severity/category {e.get('severity')!r}/{e.get('category')!r} au lieu de 0/'vuln'")
    if e.get("dedup") != f"vuln-{img}|{cve}|paq":
        faute(scen, f"dedup {e.get('dedup')!r}")


# P10.32-p — le faux `trivy` des bacs ignore `--template` : il ne prouve RIEN du template. Ce rapport, rendu
# par le VRAI moteur (`trivy convert`, sans base de vulnérabilités ni réseau), le juge quand un trivy réel est
# là (`PLUME_TRIVY_REEL`, sinon `trivy` dans le PATH) : 6e colonne = `V3Score` de la source `nvd` SEULE
# (ghsa et redhat présents et ignorés), vide sans elle ; `-` pour une version corrigée absente.
VULN_RAPPORT_TRIVY = {"SchemaVersion": 2, "ArtifactName": "reg/img:1", "ArtifactType": "container_image",
                      "Results": [{"Target": "reg/img:1 (debian 12)", "Class": "os-pkgs", "Type": "debian",
                                   "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2",
     "Severity": "CRITICAL", "CVSS": {"ghsa": {"V3Score": 5.5}, "nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 7.1}}},
    {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib", "InstalledVersion": "1.2", "Severity": "HIGH",
     "CVSS": {"ghsa": {"V3Score": 7.5}}},
    {"VulnerabilityID": "CVE-2024-0003", "PkgName": "curl", "InstalledVersion": "8.0", "FixedVersion": "8.1",
     "Severity": "HIGH"}]}]}
VULN_TSV_ATTENDU = sorted(["CRITICAL\tCVE-2024-0001\topenssl\t3.0.1\t3.0.2\t9.8",
                           "HIGH\tCVE-2024-0002\tzlib\t1.2\t-\t", "HIGH\tCVE-2024-0003\tcurl\t8.0\t8.1\t"])


def scen_vuln_template_reel(base):
    """Rend True si le template a été joué par un trivy réel, False s'il n'y en a pas (avoué en sortie)."""
    scen = "vuln-template"
    trivy = os.environ.get("PLUME_TRIVY_REEL") or shutil.which("trivy")
    if not trivy:
        return False
    with open(os.path.join(COL, "vuln.sh"), encoding="utf-8") as f:
        tpl = [l[len("TPL='"):-1] for l in f.read().splitlines() if l.startswith("TPL='") and l.endswith("'")]
    if len(tpl) != 1:
        faute(scen, f"vuln.sh : {len(tpl)} ligne(s) `TPL='…'` au lieu d'une : le template ne se juge pas")
        return True
    rapport = os.path.join(base, "trivy-rapport.json")
    with open(rapport, "w", encoding="utf-8") as f:
        json.dump(VULN_RAPPORT_TRIVY, f)
    r = subprocess.run([trivy, "convert", "--quiet", "--format", "template", "--template", tpl[0], rapport],
                       capture_output=True, text=True, timeout=120, cwd=base)
    if r.returncode != 0:
        refus(f"[{scen}] `{trivy} convert` sort en {r.returncode} : {r.stderr[:300]!r}")
    obtenu = sorted(l for l in r.stdout.split("\n") if l)
    if obtenu != VULN_TSV_ATTENDU:
        faute(scen, f"template de vuln.sh sous le vrai trivy : {obtenu!r} au lieu de {VULN_TSV_ATTENDU!r}")
    return True


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


# --- (d') ship : le fichier expédié est celui qui a été jugé (substitution pendant le passage) ----------
# Le spool est 2770 root:soc et `ship.sh` tourne en root : un membre de `soc` peut REMPLACER un nom du
# spool entre l'instant où le parcours le juge et celui où il est lu. Deux fenêtres, deux attaquants
# simulés de façon déterministe (un vrai concours de vitesse ne rougirait qu'une fois sur N) :
#   · CURL_ATTAQUANT — à l'instant où curl démarre, le nom `$SPOOL/<nom posté>` devient un lien vers un
#     secret ; curl lit ensuite le chemin qu'on lui a passé, en suivant les liens comme le vrai. Une
#     lecture EN PLACE poste le secret ; une lecture du fichier mis à l'abri poste le vrai corps.
#   · MV_ATTAQUANT — juste avant le renommage d'un fichier du spool, le nom est remplacé par un lien
#     symbolique, un lien dur ou un tube : rien ne doit être lu, l'objet est mis à l'écart, compté, avoué.
SECRET_SUBSTITUTION = "SECRET-SUBSTITUE-DE-GARDE"

CURL_ATTAQUANT = r"""#!/bin/sh
cat >/dev/null
url=""; fichier=""; prec=""
for a; do
  [ "$prec" = "--data-binary" ] && fichier=${a#@}
  prec=$a; url=$a
done
printf '%s\n' "$url" >> "$FAKE_DIR/curl.urls"
printf '%s\n' "$fichier" >> "$FAKE_DIR/curl.fichiers"
n=${fichier##*/}
@RM@ -f "$SPOOL_ATTAQUE/$n"
@LN@ -s "$SECRET_ATTAQUE" "$SPOOL_ATTAQUE/$n"
if [ -f "$fichier" ]; then cat "$fichier" >> "$FAKE_DIR/curl.corps"; printf '\n' >> "$FAKE_DIR/curl.corps"; fi
cat "$FAKE_DIR/code"
"""

# CURL_REPERTOIRE — pendant l'envoi, le nom libéré du spool devient un VRAI répertoire (non vide) de
# l'attaquant : la remise au spool doit échouer sans rien y déposer, et le fichier rester dans l'abri.
CURL_REPERTOIRE = r"""#!/bin/sh
cat >/dev/null
fichier=""; prec=""
for a; do [ "$prec" = "--data-binary" ] && fichier=${a#@}; prec=$a; done
printf '%s\n' "$fichier" >> "$FAKE_DIR/curl.fichiers"
if [ -f "$fichier" ]; then cat "$fichier" >> "$FAKE_DIR/curl.corps"; printf '\n' >> "$FAKE_DIR/curl.corps"; fi
if [ -n "${SPOOL_ATTAQUE:-}" ]; then
  n=${fichier##*/}
  @MKDIR@ "$SPOOL_ATTAQUE/$n" && : > "$SPOOL_ATTAQUE/$n/garde-attaquant"
fi
cat "$FAKE_DIR/code"
"""

# STAT_DEUX_VOLUMES — `stat -c %d` rend un autre volume pour l'abri `…/envoi` que pour le spool.
STAT_DEUX_VOLUMES = r"""#!/bin/sh
for a; do d=$a; done
case "$d" in */envoi) echo 2 ;; *) echo 1 ;; esac
"""

# STAT_LIEN_VERS_AUTRE_VOLUME — le spool est un lien symbolique : sans `-L`, `stat` rend le volume du LIEN
# (ici celui de l'abri : faux « même volume ») ; avec `-L`, celui de sa cible (un autre volume).
STAT_LIEN_VERS_AUTRE_VOLUME = r"""#!/bin/sh
suivre=0
for a; do d=$a; [ "$a" = -L ] && suivre=1; done
if [ -L "$d" ] && [ "$suivre" = 0 ]; then echo 2; exit 0; fi
case "$d" in */envoi) echo 2 ;; *) echo 1 ;; esac
"""

MV_ATTAQUANT = r"""#!/bin/sh
# dernier argument = destination ; avant-dernier = source (forme `mv -f src dst` de ship.sh)
src=""; prec=""
for a; do src=$prec; prec=$a; done
case "$src" in
  "$SPOOL_ATTAQUE"/*)
    case "$prec" in
      */envoi/*)
        # une seule substitution par passage : le second fichier, sain, doit partir
        if [ ! -e "$FAKE_DIR/journal" ]; then
          echo appel >> "$FAKE_DIR/journal"
          @RM@ -f "$src"
          case "$GENRE_ATTAQUE" in
            lien) @LN@ -s "$SECRET_ATTAQUE" "$src" ;;
            lien-dur) @LN@ "$SECRET_ATTAQUE" "$src" ;;
            tube) @MKFIFO@ "$src" ;;
            disparu) : ;;   # le nom est seulement SUPPRIMÉ : le renommage échoue, rien n'a été substitué
          esac
        fi ;;
    esac ;;
esac
exec @MV@ "$@"
"""


def remplacer_outil(bac, nom, texte):
    """Remplace l'outil `nom` du bac par un script. Le lien vers le VRAI outil est retiré d'abord :
    écrire à travers lui réécrirait le binaire du système."""
    p = os.path.join(bac.bin, nom)
    if os.path.lexists(p):
        os.remove(p)
    reels = {k: shutil.which(k) for k in ("rm", "ln", "mv", "mkfifo", "mkdir")}
    if not all(reels.values()):
        refus(f"[ship-substitution] outil réel manquant : {[k for k, v in reels.items() if not v]}")
    for k, v in reels.items():
        texte = texte.replace(f"@{k.upper()}@", v)
    bac.outil(nom, texte)


def scen_ship_substitution(base):
    env_base = {"PLUME_TOKEN": "jeton-de-garde", "PLUME_CENTRAL": "https://central.invalid"}

    # fenêtre 1 : le nom est remplacé à l'instant où curl démarre
    scen = "ship-substitution-a-la-lecture"
    bac = bac_ship(base)
    secret = os.path.join(bac.d, "secret-de-l-hote")
    open(secret, "w").write(SECRET_SUBSTITUTION)
    remplacer_outil(bac, "curl", CURL_ATTAQUANT)
    open(os.path.join(bac.spool, "a.json"), "w").write('{"vrai":"corps-a"}')
    r = bac.jouer("ship.sh", dict(env_base, SPOOL_ATTAQUE=bac.spool, SECRET_ATTAQUE=secret))
    corps = corps_curl(bac)
    if fichiers_postes(bac) != ["a.json"]:
        refus(f"[{scen}] le curl attaquant n'a pas été appelé sur a.json : {fichiers_postes(bac)!r}")
    if SECRET_SUBSTITUTION in corps:
        faute(scen, "un nom du spool remplacé par un lien PENDANT l'envoi a fait poster sa cible au central "
                    "(le fichier est lu EN PLACE, après son examen)")
    if '"corps-a"' not in corps:
        faute(scen, f"le vrai corps n'est pas expédié : {corps[:200]!r} rc={r.returncode} {r.stderr[:200]!r}")
    if r.returncode != 0:
        faute(scen, f"rc={r.returncode} {r.stderr[:200]!r}")
    if open(secret).read() != SECRET_SUBSTITUTION:
        faute(scen, "la cible du lien a été modifiée")

    # fenêtre 2 : le nom est remplacé juste avant sa mise à l'abri
    for genre in ("lien", "lien-dur", "tube"):
        scen = f"ship-substitution-avant-abri[{genre}]"
        bac = bac_ship(base)
        secret = os.path.join(bac.d, "secret-de-l-hote")
        open(secret, "w").write(SECRET_SUBSTITUTION)
        remplacer_outil(bac, "mv", MV_ATTAQUANT)
        open(os.path.join(bac.spool, "a.json"), "w").write('{"vrai":"corps-a"}')
        open(os.path.join(bac.spool, "b.json"), "w").write('{"vrai":"corps-b"}')
        envs = dict(env_base, SPOOL_ATTAQUE=bac.spool, SECRET_ATTAQUE=secret, GENRE_ATTAQUE=genre)
        r = bac.jouer("ship.sh", envs)
        if bac.appels() == 0:
            # le script n'a jamais renommé un fichier du spool vers un abri : rien n'a été mis à l'abri
            faute(scen, "aucun fichier du spool n'est mis à l'abri avant d'être lu (aucun renommage vers "
                        f"`envoi/`) : postés {fichiers_postes(bac)!r}")
            continue
        corps = corps_curl(bac)
        if SECRET_SUBSTITUTION in corps:
            faute(scen, "l'objet substitué a été lu et expédié au central")
        postes = fichiers_postes(bac)
        if len(postes) != 1:
            faute(scen, f"un seul fichier sain devait partir (l'autre est substitué) : postés {postes!r}")
        if r.returncode != 0:
            faute(scen, f"rc={r.returncode} {r.stderr[:200]!r}")
        if not os.path.exists(secret) or open(secret).read() != SECRET_SUBSTITUTION:
            faute(scen, "la cible de la substitution a été supprimée ou modifiée")
        ecartes = os.listdir(os.path.join(bac.etat, "refuses")) if os.path.isdir(os.path.join(bac.etat, "refuses")) else []
        if len(ecartes) != 1:
            faute(scen, f"l'objet substitué n'est pas mis à l'écart dans refuses/ : {ecartes!r}")
        av = [t for _, _, t, _ in enveloppes(bac.spool) if "spool-substitue" in t]
        if not av or "1 fichier(s) du spool remplacés" not in av[0]:
            faute(scen, f"aucun aveu `spool-substitue` portant le compte 1 : {[a[:200] for a in av]}")
        if "REMPLACE" not in r.stderr:
            faute(scen, f"la substitution n'est pas dite sur stderr : {r.stderr[:200]!r}")

    # un nom SEULEMENT DISPARU avant sa mise à l'abri (supprimé par un autre, pas remplacé) : le renommage
    # échoue, et ce n'est PAS une substitution — l'avouer « SPOOL ALTÉRÉ » confondrait deux causes
    scen = "ship-disparu-avant-abri"
    bac = bac_ship(base)
    secret = os.path.join(bac.d, "secret-de-l-hote")
    open(secret, "w").write(SECRET_SUBSTITUTION)
    remplacer_outil(bac, "mv", MV_ATTAQUANT)
    open(os.path.join(bac.spool, "a.json"), "w").write('{"vrai":"corps-a"}')
    open(os.path.join(bac.spool, "b.json"), "w").write('{"vrai":"corps-b"}')
    r = bac.jouer("ship.sh", dict(env_base, SPOOL_ATTAQUE=bac.spool, SECRET_ATTAQUE=secret, GENRE_ATTAQUE="disparu"))
    if bac.appels() != 1:
        faute(scen, f"aucun fichier du spool n'est renommé vers `envoi/` (le faux mv n'a rien fait disparaître) : "
                    f"{bac.appels()} appel(s), postés {fichiers_postes(bac)!r}")
    av = [t for _, _, t, _ in enveloppes(bac.spool) if "spool-substitue" in t]
    if av or "REMPLACE" in r.stderr:
        faute(scen, f"un fichier seulement DISPARU avant sa mise à l'abri est avoué comme SUBSTITUÉ (l'échec du "
                    f"renommage n'arrête pas le traitement) : {[a[:160] for a in av]} {r.stderr[:200]!r}")
    refuses_d = os.path.join(bac.etat, "refuses")
    if os.path.isdir(refuses_d) and os.listdir(refuses_d):
        faute(scen, f"un fichier disparu laisse un objet dans refuses/ : {os.listdir(refuses_d)!r}")
    if len(fichiers_postes(bac)) != 1 or '"corps-b"' not in corps_curl(bac) or r.returncode != 0:
        faute(scen, f"le fichier sain resté au spool ne part pas : postés {fichiers_postes(bac)!r} rc={r.returncode}")

    # un envoi interrompu (fichier laissé dans l'abri par une coupure) est repris
    scen = "ship-envoi-interrompu-repris"
    bac = bac_ship(base)
    abri = os.path.join(bac.etat, "envoi")
    os.makedirs(abri)
    open(os.path.join(abri, "reste.json"), "w").write('{"vrai":"reste"}')
    r = bac.jouer("ship.sh", env_base)
    if '"reste"' not in corps_curl(bac) or os.path.exists(os.path.join(abri, "reste.json")):
        faute(scen, f"un fichier laissé dans l'abri n'est pas repris : postés {fichiers_postes(bac)!r} rc={r.returncode}")

    # DEUX liens laissés dans l'abri (coupure avant le jugement), dont un PENDANT (sa cible n'existe pas :
    # `[ -e ]` le dit absent) : ni lus, ni rendus au spool, ni `chmod` (qui suivrait le lien et changerait
    # le mode de sa cible) — tous deux mis à l'écart, et l'aveu porte le compte 2 (un compte figé à 1 ou
    # un lien pendant ignoré passeraient pour tenus avec un seul objet)
    scen = "ship-envoi-interrompu-lien"
    bac = bac_ship(base)
    secret = os.path.join(bac.d, "secret-de-l-hote")
    open(secret, "w").write(SECRET_SUBSTITUTION)
    os.chmod(secret, 0o600)
    abri = os.path.join(bac.etat, "envoi")
    os.makedirs(abri)
    os.symlink(secret, os.path.join(abri, "lien.json"))
    os.symlink(os.path.join(bac.d, "cible-absente"), os.path.join(abri, "pendant.json"))
    r = bac.jouer("ship.sh", env_base)
    if SECRET_SUBSTITUTION in corps_curl(bac) or os.path.lexists(os.path.join(bac.spool, "lien.json")) \
            or os.path.lexists(os.path.join(bac.spool, "pendant.json")):
        faute(scen, f"un lien laissé dans l'abri est lu ou rendu au spool : postés {fichiers_postes(bac)!r}")
    if stat.S_IMODE(os.stat(secret).st_mode) != 0o600:
        faute(scen, f"le mode de la cible d'un lien laissé dans l'abri a changé : {oct(os.stat(secret).st_mode)}")
    restes = sorted(os.listdir(abri)) if os.path.isdir(abri) else []
    if restes:
        faute(scen, f"un lien laissé dans l'abri y reste (un lien PENDANT est ignoré ?) : {restes!r}")
    av = [t for _, _, t, _ in enveloppes(bac.spool) if "spool-substitue" in t]
    if not av or "2 fichier(s) du spool remplacés" not in av[0]:
        faute(scen, f"aucun aveu `spool-substitue` portant le compte 2 (deux liens laissés dans l'abri) : "
                    f"{[a[:200] for a in av]}")

    # l'abri est PRIVÉ : un `envoi/` trouvé en 0755 est ramené à 0700 (sinon sa privauté ne tiendrait qu'au
    # mode de `$STATE`, posé par l'installeur)
    scen = "ship-abri-prive"
    bac = bac_ship(base)
    abri = os.path.join(bac.etat, "envoi")
    os.makedirs(abri)
    os.chmod(abri, 0o755)
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", env_base)
    if stat.S_IMODE(os.stat(abri).st_mode) != 0o700:
        faute(scen, f"l'abri d'envoi n'est pas privé : mode {oct(stat.S_IMODE(os.stat(abri).st_mode))} rc={r.returncode}")

    # RÉESSAI SOUS ATTAQUE : pendant l'envoi, le nom libéré du spool devient un lien vers un RÉPERTOIRE.
    # La remise au spool ne doit pas suivre ce lien (`mv` sans `-T` dépose le fichier, nom et contenu de
    # l'attaquant, DANS ce répertoire, en écrasant le fichier de même nom).
    scen = "ship-remise-lien-vers-repertoire"
    bac = bac_ship(base, code="503")
    cible = os.path.join(bac.d, "repertoire-cible")
    os.makedirs(cible)
    open(os.path.join(cible, "a.json"), "w").write("ORIGINAL-DE-LA-CIBLE")
    remplacer_outil(bac, "curl", CURL_ATTAQUANT)
    open(os.path.join(bac.spool, "a.json"), "w").write('{"contenu":"ATTAQUANT"}')
    mode_cible = stat.S_IMODE(os.stat(cible).st_mode)
    r = bac.jouer("ship.sh", dict(env_base, SPOOL_ATTAQUE=bac.spool, SECRET_ATTAQUE=cible))
    if fichiers_postes(bac) != ["a.json"]:
        refus(f"[{scen}] le curl attaquant n'a pas été appelé sur a.json : {fichiers_postes(bac)!r}")
    if stat.S_IMODE(os.stat(cible).st_mode) != mode_cible:
        # un `chmod` du spool a suivi le lien : le fichier est traité EN PLACE (jamais mis à l'abri)
        faute(scen, f"la remise au spool a suivi un lien vers un répertoire et en a changé le mode "
                    f"({oct(mode_cible)} -> {oct(stat.S_IMODE(os.stat(cible).st_mode))}) : le fichier est "
                    "traité EN PLACE dans le spool, pas depuis l'abri")
        os.chmod(cible, mode_cible)   # rendu lisible : la suite du jugement nomme le reste
    if sorted(os.listdir(cible)) != ["a.json"] or open(os.path.join(cible, "a.json")).read() != "ORIGINAL-DE-LA-CIBLE":
        faute(scen, "la remise au spool a suivi un lien vers un répertoire et y a déposé le fichier : "
                    f"{sorted(os.listdir(cible))!r} {open(os.path.join(cible, 'a.json')).read()[:80]!r}")
    remis = os.path.join(bac.spool, "a.json")
    if os.path.islink(remis) or not os.path.isfile(remis) or open(remis).read() != '{"contenu":"ATTAQUANT"}':
        faute(scen, f"le fichier gardé pour réessai n'est pas revenu au spool sous son nom : lien={os.path.islink(remis)}")

    # RÉESSAI SOUS ATTAQUE, VRAI RÉPERTOIRE : le nom libéré devient un répertoire de l'attaquant. `mv -T`
    # échoue (on ne remplace pas un répertoire par un fichier) : rien n'est déposé DEDANS, le fichier reste
    # dans l'abri, l'échec est dit, et le passage suivant le reprend une fois le nom libre.
    scen = "ship-remise-repertoire-reel"
    bac = bac_ship(base, code="503")
    remplacer_outil(bac, "curl", CURL_REPERTOIRE)
    open(os.path.join(bac.spool, "a.json"), "w").write('{"vrai":"corps-a"}')
    r = bac.jouer("ship.sh", dict(env_base, SPOOL_ATTAQUE=bac.spool))
    pose = os.path.join(bac.spool, "a.json")
    abri = os.path.join(bac.etat, "envoi")
    if fichiers_postes(bac) != ["a.json"] or not os.path.isdir(pose):
        # le nom n'était pas LIBRE pendant l'envoi : le fichier n'a pas quitté le spool avant d'être lu
        faute(scen, f"le nom du fichier envoyé n'est pas libre dans le spool pendant l'envoi (lu EN PLACE, pas "
                    f"depuis l'abri) : postés {fichiers_postes(bac)!r}")
    else:
        if sorted(os.listdir(pose)) != ["garde-attaquant"]:
            faute(scen, f"la remise au spool a déposé le fichier DANS le répertoire posé à son nom : {sorted(os.listdir(pose))!r}")
        garde = os.path.join(abri, "a.json")
        if not os.path.isfile(garde) or open(garde).read() != '{"vrai":"corps-a"}':
            faute(scen, f"le fichier gardé pour réessai n'est plus dans l'abri (perdu ou déposé ailleurs) : "
                        f"abri={sorted(os.listdir(abri)) if os.path.isdir(abri) else None}")
        if "remise au spool impossible" not in r.stderr or r.returncode != 0:
            faute(scen, f"l'échec de la remise au spool n'est pas dit : rc={r.returncode} {r.stderr[:300]!r}")
        shutil.rmtree(pose)
        bac.poser("code", "202")
        open(os.path.join(bac.fake, "curl.corps"), "w").close()
        r = bac.jouer("ship.sh", env_base)
        if '"corps-a"' not in corps_curl(bac) or os.path.lexists(garde) or visibles(bac.spool):
            faute(scen, f"le fichier resté dans l'abri n'est pas repris au passage suivant : corps={corps_curl(bac)[:120]!r} "
                        f"spool={visibles(bac.spool)} rc={r.returncode}")

    # DEUX VOLUMES : `mv` recopie, `-links 1` ne voit plus le lien dur ; sans fs.protected_hardlinks=1 la
    # défense est ouverte et ship le dit à chaque passage. Témoins inverses : même volume, ou sysctl à 1.
    # Le sysctl s'écrit aussi SANS saut de ligne (`read` y rend 1 après avoir lu, comme dash sur le vrai /proc),
    # et ABSENT (`valeur` None : lecture ratée, dite « inconnu », jamais prise pour une protection).
    for nom, deux_volumes, valeur, fin, attendu in (
            ("ship-lien-dur-deux-volumes-sans-protection", True, "0", "\n", True),
            ("ship-lien-dur-deux-volumes-protege", True, "1", "\n", False),
            ("ship-lien-dur-deux-volumes-protege-sans-saut-de-ligne", True, "1", "", False),
            ("ship-lien-dur-deux-volumes-sysctl-illisible", True, None, "", True),
            ("ship-lien-dur-spool-lien-vers-autre-volume", "lien", "0", "\n", True),
            ("ship-lien-dur-meme-volume", False, "0", "\n", False)):
        bac = bac_ship(base)
        if deux_volumes == "lien":
            remplacer_outil(bac, "stat", STAT_LIEN_VERS_AUTRE_VOLUME)
        elif deux_volumes:
            remplacer_outil(bac, "stat", STAT_DEUX_VOLUMES)
        proc = os.path.join(bac.d, "proc")
        os.makedirs(os.path.join(proc, "sys", "fs"))
        if valeur is not None:
            open(os.path.join(proc, "sys", "fs", "protected_hardlinks"), "w").write(valeur + fin)
        env_cas = dict(env_base, PLUME_PROC_ROOT=proc)
        if deux_volumes == "lien":
            reel = bac.spool + "-reel"
            os.rename(bac.spool, reel)
            os.symlink(reel, bac.spool)
        open(os.path.join(bac.spool, "a.json"), "w").write("{}")
        r = bac.jouer("ship.sh", env_cas)
        dit = ("ATTENTION" in r.stderr and f"fs.protected_hardlinks={valeur or 'inconnu'}" in r.stderr
               and "deux volumes" in r.stderr)
        if dit != attendu or r.returncode != 0 or fichiers_postes(bac) != ["a.json"]:
            faute(nom, f"lien dur entre volumes : avertissement {'attendu' if attendu else 'NON attendu'}, "
                       f"dit={dit} rc={r.returncode} postés={fichiers_postes(bac)!r} {r.stderr[:200]!r}")

    # REFUS PERMANENT dont la mise à l'écart est impossible (`refuses` n'est pas un répertoire) : le fichier
    # revient au spool, il ne reste pas dans l'abri
    scen = "ship-refus-permanent-sans-ecart"
    bac = bac_ship(base, code="400")
    open(os.path.join(bac.etat, "refuses"), "w").write("pas un répertoire")
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", env_base)
    abri = os.path.join(bac.etat, "envoi")
    dans_l_abri = os.listdir(abri) if os.path.isdir(abri) else []
    if visibles(bac.spool) != ["a.json"] or dans_l_abri or "mise à l'écart impossible" not in r.stderr:
        faute(scen, f"un refus permanent non écartable n'est pas rendu au spool : spool={visibles(bac.spool)} "
                    f"abri={dans_l_abri} {r.stderr[:200]!r}")

    # l'unité livrée déclare l'état inscriptible elle-même (sans lui, ship refuse tout en code 2) : le drop-in
    # commun ne la couvre que si elle est posée par `install_collector`
    scen = "ship-unite-etat-inscriptible"
    unite = open(os.path.join(RACINE, "systemd", "plume-ship.service"), encoding="utf-8").read()
    rw = [m for l in unite.splitlines() if l.startswith("ReadWritePaths=") for m in l.split("=", 1)[1].split()]
    if "/var/lib/plume/state" not in rw:
        faute(scen, f"systemd/plume-ship.service ne déclare pas /var/lib/plume/state inscriptible : {rw!r}")

    # réessai : le fichier conservé revient au spool
    scen = "ship-reessai-revient-au-spool"
    bac = bac_ship(base, code="503")
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", env_base)
    abri = os.path.join(bac.etat, "envoi")
    dans_l_abri = os.listdir(abri) if os.path.isdir(abri) else []
    if visibles(bac.spool) != ["a.json"] or dans_l_abri:
        faute(scen, f"un fichier conservé pour réessai n'est pas rendu au spool : spool={visibles(bac.spool)} "
                    f"abri={dans_l_abri}")

    # sans abri possible : refus nommé, code 2, rien d'expédié, spool conservé
    scen = "ship-sans-abri"
    bac = bac_ship(base)
    pas_un_rep = os.path.join(bac.d, "etat-est-un-fichier")
    open(pas_un_rep, "w").write("x")
    open(os.path.join(bac.spool, "a.json"), "w").write("{}")
    r = bac.jouer("ship.sh", dict(env_base, PLUME_STATE=pas_un_rep))
    if r.returncode != 2 or appels_curl(bac) or visibles(bac.spool) != ["a.json"] or "REFUS" not in r.stderr:
        faute(scen, f"sans répertoire privé, ship doit refuser en code 2 sans rien expédier : rc={r.returncode} "
                    f"curl={appels_curl(bac)} spool={visibles(bac.spool)} {r.stderr[:200]!r}")


def scen_bans_cscli_sans_jq_a_cote(base, awk, tag):
    """fail2ban lisible + cscli PRÉSENT sans jq : le battement ne publie pas un sous-total comme total."""
    scen = f"bans-f2b-et-cscli-sans-jq/{tag}"
    bac = Bac(base, awk, faux=("fail2ban-client", "cscli"), sans=("jq",))
    bac.poser("f2b/status", F2B_STATUS)
    bac.poser("f2b/jail.sshd", f2b_jail(["192.0.2.1"]))
    bac.poser("decisions.json", json.dumps([{"decisions": [{"value": "192.0.2.50", "scenario": "s"}]}]))
    r = bac.jouer("bans.sh", {"PLUME_CSCLI": os.path.join(bac.bin, "cscli")})
    exiger_appel(scen, bac)
    if r.returncode != 0:
        faute(scen, f"sortie {r.returncode} : {r.stderr[:300]}")
    evs, _ = evenements(scen, bac.spool)
    bt = battements(evs)
    if len(bt) != 1:
        faute(scen, f"un battement attendu (le capteur reste vivant) : {bt}")
    if any("active_bans" in (e.get("fields") or {}) for e in evs):
        faute(scen, "`active_bans` publié alors que CrowdSec, présent, n'a pas été lu : un sous-total passe pour le total")
    av = [a for a in aveux_indispo(evs, "fail2ban") if "crowdsec" in (a.get("fields") or {}).get("detail", "")]
    if not av:
        faute(scen, f"aucun aveu nommant CrowdSec non lu : {aveux_indispo(evs, 'fail2ban')}")
    if sorted(e.get("src_ip") for e in evs if e.get("category") == "ban") != ["192.0.2.1"]:
        faute(scen, "le ban fail2ban lisible n'est plus publié")


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


# --- (h) un corps de requête en ligne n'est jamais lu comme un FICHIER LOCAL ----------------
# curl lit un argument de `-d`/`--data`/`--data-ascii`/`--data-binary` (et `--data-urlencode`, `--json`) qui
# COMMENCE par « @ » comme le CHEMIN d'un fichier, et en envoie le contenu. `--data-raw` ne le fait jamais.
# Les seuls envois admis sous ces options sont ceux d'un fichier CHOISI PAR LE SCRIPT, nommés ci-dessous.
OPTIONS_CORPS_LU_COMME_FICHIER = ("-d", "--data", "--data-ascii", "--data-binary", "--data-urlencode", "--json")
# Options courtes de curl qui prennent un argument : elles terminent une grappe (`-sd x` = `-s -d x`).
COURTES_A_ARGUMENT = set("dHKowmuFeAbcETxXryYzCDPQtU")
ENVOI_DE_FICHIER_ADMIS = {
    # le fichier est un lot du spool que `ship.sh` a lui-même choisi (`find … -type f`, liens écartés)
    "ship.sh": "lot du spool expédié tel quel : `--data-binary @\"$1\"`, chemin choisi par l'éviction",
    # le fichier est le temporaire où `prom-scrape.sh` a écrit la mesure (`mktemp`), jamais une donnée lue
    "prom-scrape.sh": "mesures assemblées dans son propre `mktemp` : `--data-binary @\"$_pb\"`",
}
FORME_FICHIER_ADMISE = re.compile(r'^@"\$\{?([A-Za-z_][A-Za-z0-9_]*|[0-9])\}?"$')   # @"$var" ou @"$1"


def mots_de_curl(texte):
    """Rend la liste des invocations de curl du script : pour chacune, ses mots BRUTS (guillemets gardés),
    jusqu'au premier `|`, `;`, `&` ou `)` hors guillemets. Commentaires et suites de ligne retirés."""
    texte = texte.replace("\\\n", " ")
    # `pile` : une substitution `$(…)` ouverte DANS des guillemets doubles y est analysée hors guillemets
    # (`x="$(… | curl …)"`), et ses guillemets reprennent à sa parenthèse fermante.
    invocations, mots, mot, q, dans_curl, pile, prof = [], [], "", None, False, [], 0
    i, n = 0, len(texte)

    def finir_mot():
        nonlocal mot
        if mot:
            mots.append(mot)
        mot = ""

    def finir_invocation():
        nonlocal mots, dans_curl
        finir_mot()
        if dans_curl and mots:
            invocations.append(mots)
        mots, dans_curl = [], False

    while i < n:
        c = texte[i]
        if q:
            mot += c
            if c == "\\" and q == '"' and i + 1 < n:
                mot += texte[i + 1]; i += 2; continue
            if c == q:
                q = None
            elif q == '"' and texte.startswith("$(", i):
                pile.append(prof); prof = 0; q = None; mot += "("; i += 2
                continue
            i += 1
            continue
        if c in "'\"":
            q = c; mot += c; i += 1; continue
        if c == "#" and not mot:
            j = texte.find("\n", i)
            i = n if j < 0 else j
            continue
        if c.isspace():
            finir_mot()
            if not dans_curl and mots and mots[-1] == "curl":
                dans_curl = True; mots = []
            elif not dans_curl:
                mots = mots[-1:]
            if c == "\n":
                finir_invocation()
            i += 1
            continue
        if c == "(":
            prof += 1
        if c == ")":
            if prof == 0 and pile:
                finir_mot()
                if not dans_curl and mots and mots[-1] == "curl":
                    dans_curl = True; mots = []
                finir_invocation()
                prof = pile.pop(); q = '"'; mot = '"'; i += 1
                continue
            prof = max(prof - 1, 0)
        if c in "|;&()`":
            finir_mot()
            if not dans_curl and mots and mots[-1] == "curl":
                dans_curl = True; mots = []
            finir_invocation()
            i += 1
            continue
        mot += c
        i += 1
    finir_invocation()
    return invocations


def corps_lus_comme_fichier(mots):
    """Rend [(option, argument)] des corps envoyés sous une option qui lit « @… » comme un fichier."""
    out, k = [], 0
    while k < len(mots):
        m = mots[k]
        nxt = mots[k + 1] if k + 1 < len(mots) else ""
        if m in OPTIONS_CORPS_LU_COMME_FICHIER:
            out.append((m, nxt)); k += 2; continue
        lon = next((o for o in OPTIONS_CORPS_LU_COMME_FICHIER if o.startswith("--") and m.startswith(o + "=")), None)
        if lon:
            out.append((lon, m[len(lon) + 1:])); k += 1; continue
        if m.startswith("-") and not m.startswith("--") and len(m) > 1:
            for j, ch in enumerate(m[1:], start=1):
                if ch in COURTES_A_ARGUMENT:
                    if ch == "d":
                        reste = m[j + 1:]
                        out.append(("-d", reste if reste else nxt))
                        if not reste:
                            k += 1
                    elif not m[j + 1:]:
                        k += 1          # l'argument de l'option courte est le mot suivant : on le saute
                    break
        k += 1
    return out


def scen_corps_jamais_lu_comme_fichier_statique():
    """Tout envoi de corps sous une option qui lit « @… » comme un fichier est REFUSÉ dans collectors/**/*.sh,
    sauf la forme `@"$<variable>"` dans un script NOMMÉ par `ENVOI_DE_FICHIER_ADMIS` ; une exception qui ne
    sert plus est une faute (liste orpheline) ; l'instrument doit voir les quatre envois de corps en ligne."""
    scen = "corps-en-ligne/statique"
    scripts = sorted(glob.glob(os.path.join(COL, "**", "*.sh"), recursive=True))
    if len(scripts) < 30:
        refus(f"[{scen}] {len(scripts)} script(s) de capteur trouvés : l'arbre lu n'est pas celui des capteurs")
    servies, bruts = set(), {}
    for p in scripts:
        nom = os.path.relpath(p, COL)
        invocs = mots_de_curl(open(p, encoding="utf-8", errors="surrogateescape").read())
        # envois porteurs d'un corps, quelle que soit l'option : la validité du découpage ne dépend pas du correctif
        bruts[nom] = sum(1 for m in invocs if "--data-raw" in m or corps_lus_comme_fichier(m))
        for mots in invocs:
            for opt, arg in corps_lus_comme_fichier(mots):
                if nom in ENVOI_DE_FICHIER_ADMIS and FORME_FICHIER_ADMISE.match(arg):
                    servies.add(nom)
                    continue
                faute(scen, f"collectors/{nom} : `curl … {opt} {arg}` — un corps en ligne qui commencerait par « @ » "
                            f"serait lu comme un FICHIER LOCAL et envoyé : `--data-raw` (ou une exception nommée "
                            f"de `ENVOI_DE_FICHIER_ADMIS` pour un fichier choisi par le script)")
    for nom in sorted(set(ENVOI_DE_FICHIER_ADMIS) - servies):
        faute(scen, f"exception `{nom}` de `ENVOI_DE_FICHIER_ADMIS` orpheline : aucun envoi `@\"$fichier\"` ne la sert")
    attendus = {"respond.sh": 2, "cloudflare.sh": 1, "cloudflare-http.sh": 1}
    for nom, nb in attendus.items():
        if bruts.get(nom, 0) < nb:
            refus(f"[{scen}] l'analyse ne voit que {bruts.get(nom, 0)} envoi(s) de corps dans collectors/{nom} "
                  f"(au moins {nb} attendu(s)) : le découpage des invocations de curl ne mesure rien")


# Faux curl FIDÈLE sur ce point : comme le vrai, `-d`/`--data`/`--data-ascii`/`--data-binary` (et
# `--data-urlencode`, `--json`) suivis d'un argument « @chemin » LISENT le fichier et envoient son contenu ;
# `--data-raw` envoie l'argument tel quel. Chaque lecture de fichier est journalisée dans `$FAKE_DIR/lus`,
# chaque corps envoyé dans `$FAKE_DIR/corps` ; `-o` reçoit la réponse et `-w` rend le statut, comme curl.
CURL_FIDELE_AU_AROBASE = r"""#!/bin/sh
entree=$(cat 2>/dev/null)
corps=""; sortie=""; format=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d|--data|--data-ascii|--data-binary|--data-urlencode|--json)
      case "$2" in
        @*) f=${2#@}; printf '%s\n' "$f" >> "$FAKE_DIR/lus"; corps=$(cat "$f" 2>/dev/null) ;;
        *) corps=$2 ;;
      esac; shift ;;
    --data-raw) corps=$2; shift ;;
    -o) sortie=$2; shift ;;
    -w) format=$2; shift ;;
    -K|-m|-H|--max-time|--max-filesize) shift ;;
  esac
  shift
done
printf '%s\n' "$corps" >> "$FAKE_DIR/corps"
reponse='{"ok":true}'
if [ -n "$sortie" ] && [ "$sortie" != /dev/null ]; then printf '%s' "$reponse" > "$sortie"
elif [ -z "$sortie" ]; then printf '%s' "$reponse"; fi
case "$format" in *'\n'*) printf '\n200' ;; ?*) printf 200 ;; esac
exit 0
"""
SECRET_TEMOIN = "contenu-du-fichier-temoin-qui-ne-doit-jamais-partir"


def extraire(nom, debut, fin_re, scen, apres=None):
    """Texte LIVRÉ de `collectors/<nom>` : de la première ligne qui commence par `debut` à la première ligne
    qui satisfait `fin_re` — cherchée à partir de la ligne qui commence par `apres` s'il est donné.
    Introuvable -> refus (une extraction vide ne mesurerait rien)."""
    lignes = open(os.path.join(COL, nom), encoding="utf-8").read().split("\n")
    i = next((k for k, l in enumerate(lignes) if l.startswith(debut)), None)
    if i is None:
        refus(f"[{scen}] `{debut}` introuvable dans collectors/{nom} : le témoin ne joue plus le texte livré")
    a = i if apres is None else next((k for k in range(i, len(lignes)) if lignes[k].startswith(apres)), None)
    if a is None:
        refus(f"[{scen}] `{apres}` introuvable dans collectors/{nom} après `{debut}`")
    j = next((k for k in range(a, len(lignes)) if re.search(fin_re, lignes[k])), None)
    if j is None:
        refus(f"[{scen}] fin de l'extraction introuvable dans collectors/{nom}")
    return "\n".join(lignes[i:j + 1]) + "\n"


def jouer_corps_arobase(base, scen, prelude, texte_livre, appel, sans_mktemp=False):
    bac = Bac(base, None, sans=("mktemp",) if sans_mktemp else ())
    bac.outil("curl", CURL_FIDELE_AU_AROBASE)
    if sans_mktemp:
        bac.outil("mktemp", "#!/bin/sh\nexit 1\n")
    temoin = os.path.join(bac.d, "fichier-temoin")
    with open(temoin, "w") as f:
        f.write(SECRET_TEMOIN + "\n")
    corps = "@" + temoin
    prog = os.path.join(bac.d, "joue.sh")
    with open(prog, "w") as f:
        f.write(prelude + texte_livre + appel)
    r = subprocess.run([SH, prog, corps], env={"PATH": bac.bin, "FAKE_DIR": bac.fake, "LC_ALL": "C.UTF-8",
                                               "HOME": bac.d}, capture_output=True, text=True, timeout=60,
                       cwd=bac.d, stdin=subprocess.DEVNULL)
    pc, pl = os.path.join(bac.fake, "corps"), os.path.join(bac.fake, "lus")
    envoyes = open(pc).read() if os.path.exists(pc) else None
    if envoyes is None:
        refus(f"[{scen}] le faux curl n'a jamais été appelé : le témoin ne mesure rien ({r.stderr[:300]!r})")
    if os.path.exists(pl) or SECRET_TEMOIN in envoyes:
        faute(scen, f"le corps « @{temoin} » a été LU COMME UN FICHIER et son contenu envoyé "
                    f"(lus={open(pl).read() if os.path.exists(pl) else ''!r}, corps={envoyes[:200]!r})")
    elif envoyes.strip("\n") != corps:
        faute(scen, f"le corps envoyé n'est pas l'argument tel quel : {envoyes[:200]!r} au lieu de {corps!r}")


def scen_corps_jamais_lu_comme_fichier(base):
    """Les quatre envois en ligne LIVRÉS (remise du verdict de `respond.sh`, avec et sans `mktemp` ; requête
    GraphQL des deux capteurs Cloudflare), extraits du script et joués avec un corps « @<fichier témoin> »
    sous un faux curl fidèle : le fichier témoin n'est JAMAIS lu, l'argument part tel quel."""
    scen_corps_jamais_lu_comme_fichier_statique()
    resp = extraire("respond.sh", "RESULTAT_CORPS_FICHIER=", r"^}$", "corps-en-ligne/respond",
                    apres="remettre_une_fois()")
    if "remettre_une_fois()" not in resp:
        refus("[corps-en-ligne/respond] `remettre_une_fois` hors de l'extraction : le témoin ne joue pas la remise")
    prelude = ('HH=""; TLS=""; CENTRAL="https://central.invalid:7000"\n'
               "resp_curl_auth_stdin() { printf 'header = \"Authorization: Bearer x\"\\n'; }\n")
    for sans in (False, True):
        jouer_corps_arobase(base, f"corps-en-ligne/respond{'-sans-mktemp' if sans else ''}", prelude, resp,
                            'remettre_une_fois "$1"\n', sans_mktemp=sans)
    for nom in ("cloudflare.sh", "cloudflare-http.sh"):
        envoi = extraire(nom, "resp=$(plume_curlcfg_header_auth", r"\|\| true\)\s*$", f"corps-en-ligne/{nom}")
        prelude = ('TOKEN="jeton-de-garde"; API="https://api.cloudflare.invalid/graphql"; body=$1\n'
                   "plume_curlcfg_header_auth() { printf 'header = \"Authorization: Bearer %s\"\\n' \"$1\"; }\n")
        jouer_corps_arobase(base, f"corps-en-ligne/{nom}", prelude, envoi, "")


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
              "respond.sh", "prom-scrape.sh", "engagement-adapter.sh", "kube-audit.sh", "minio-audit-relay.py",
              "cloudflare.sh", "cloudflare-http.sh"):
        if not os.path.isfile(os.path.join(COL, s)):
            refus(f"collectors/{s} introuvable")
    awks = [(a, shutil.which(a)) for a in AWK_EXERCES if shutil.which(a)]
    if not awks:
        refus(f"aucun awk exercé présent parmi {AWK_EXERCES}")
    base = tempfile.mkdtemp(prefix="plume-collecte-sure-")
    try:
        scen_corps_jamais_lu_comme_fichier(base)   # d'abord : un statique pur, indépendant des bacs
        for tag, awk in awks:
            scen_clamav(base, awk, tag)
            scen_yara(base, awk, tag)
            scen_vuln(base, awk, tag)
            scen_vuln_colonnes_hostiles(base, awk, tag)
            scen_imgdrift(base, awk, tag)
            scen_bans_sans_backend(base, awk, tag)
            scen_bans_presents(base, awk, tag)
            scen_bans_cscli_sans_jq_a_cote(base, awk, tag)
            scen_crowdsec_alertes(base, awk, tag)
        tpl_joue = scen_vuln_template_reel(base)
        scen_ship(base)
        scen_ship_substitution(base)
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
          "kube-audit échappée, parcours du spool sûr, relais fermé sans jeton, aucun corps en ligne lu comme fichier ; template trivy de vuln : "
          + ("joué par un trivy réel." if tpl_joue else "NON JOUÉ (aucun trivy réel : PLUME_TRIVY_REEL ou PATH)."))
    return 0


SH = None
BASH = None

if __name__ == "__main__":
    sys.exit(main())
