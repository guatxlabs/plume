#!/usr/bin/env python3
"""Le capteur CrowdSec dit ce que le moteur LIT, et refuse de conclure quand il ne lit rien — garde de
CI (`P10.32-g`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`collectors/crowdsec.sh` émettait un battement de santé (scénarios chargés, scénarios cassés, agent
joignable, LAPI joignable) et RIEN sur ce que CrowdSec lisait. Une acquisition tombée à zéro ligne —
fichier de journal renommé à la recréation d'un pod, chemin faux, montage perdu — laissait la source
« fraîche » avec zéro alerte : indiscernable du calme, alors que `cscli metrics show acquisition
-o json` porte, par source, les compteurs `reads`, `parsed`, `unparsed`, `pour`, `whitelisted`.

CE QUE LA GARDE FAIT
--------------------
Elle JOUE le capteur LIVRÉ (`collectors/crowdsec.sh`, ou le chemin passé en argument — c'est ainsi
qu'une mutation s'éprouve), dans un bac : `PATH` réduit aux seuls outils dont le capteur a besoin (ni
`kubectl` ni `k3s` : un exécuteur d'intégration qui les porte ferait sinon chercher un agent kube),
`PLUME_CSCLI` pointé sur un FAUX `cscli` qui rend des sorties JSON fabriquées, spool et état dans un
répertoire temporaire. Les scénarios, chacun en un ou deux passages qui partagent l'état local :
  · sain             — premier passage `premier_passage` (différences -1, aucun refus), second passage
                       `lit` avec les compteurs et différences EXACTS par source et au total (valeurs
                       toutes distinctes : deux compteurs permutés rougissent), la source figée
                       nommée dans `acq_frozen_sources`, sévérité 0, aucun aveu d'acquisition ;
  · figé             — même lecture, une source neuve encore vide : `aucune_lecture`, sévérité >= 3,
                       aveu de cause `source_absente`, état NON avancé (l'état avancé porterait la
                       source neuve : la comparaison est discriminante) ;
  · aucune source    — `{"acquisition":{}}` et `{}` sur un état déjà posé : `aucune_source`, sévérité
                       >= 3, aveu, état NON avancé (il vaudrait `{}`) ;
  · aucune analyse   — lignes lues, aucune analysée ni en liste blanche (au premier passage puis sur
                       l'intervalle) : `aucune_analyse`, cause `forme_inconnue`, état non avancé ;
  · état abîmé       — état précédent VIDE (0 octet), JSON de mauvaise forme ou non-JSON : traité en
                       premier passage, jamais en `illisible` (un refus n'écrit pas l'état, rien ne
                       le réparerait) ;
  · cent cinquante sources — `acq_sources` et les totaux couvrent les 150, le détail et
                       `acq_frozen_sources` sont bornés à 100 ; et quand SEULE la 150e lit (hors du
                       détail), les différences totales la comptent : `lit`, pas `aucune_lecture` ;
  · une source lit sans analyser parmi d'autres qui analysent — `lit`, et elle n'est PAS nommée
                       figée (elle lit) ; sur tout refus, `acq_frozen_sources` reste vide ;
  · liste blanche    — lignes lues, aucune analysée mais toutes en liste blanche : jamais
                       `aucune_analyse`, et depuis `P10.32-k` jamais `lit` non plus — c'est
                       `tout_en_liste_blanche`, un refus (cause `forme_inconnue`), sur deux passages ;
                       les échantillons « sains » portent une part en liste blanche SOUS le seuil
                       (les verdicts de liste blanche sont éprouvés par la garde de `P10.32-k`) ;
  · état impossible à poser — répertoire d'état sous un fichier : battement présent, aveu
                       `etat/acquisition` ;
  · clé stable       — `aucune_analyse` répété sur un état figé (lignes lues qui grandissent) : même
                       empreinte de clé de dédoublonnage d'un passage à l'autre ;
  · illisible        — `cscli metrics` en échec (cause `source_illisible`), une sortie qui n'est pas
                       du JSON, une sortie VIDE rendue avec le code 0, un compteur non numérique
                       (cause `forme_inconnue`) : `illisible`, compteurs -1, aveu, état non avancé ;
  · redémarrage      — compteurs qui DIMINUENT et source neuve : `lit`, `acq_counters_reset` vrai,
                       différence = valeur courante, JAMAIS un négatif ;
  · rien depuis le démarrage — premier passage dont toutes les sources sont à zéro : `aucune_lecture`,
                       aucun état posé ;
  · cscli ancien     — `metrics show` absent, `metrics -o json` présent : le repli lit les compteurs.
Dans tous les cas : sortie 0, un battement `category=health` présent (son silence lèverait MUET), et
ses champs inclus dans l'en-tête `# plume-emits:` du capteur ; sur un refus, le message du battement
dit `ACQUISITION <verdict>`, et ne le dit pas sur un moteur qui lit. Le faux `cscli` n'exige pas
seulement le verbe : il ne rend l'échantillon qu'à `metrics show acquisition -o json` et à
`metrics -o json`, et répond aux autres sections et formats comme un vrai `cscli` (code 0, sans
acquisition).

L'INSTRUMENT SE VALIDE AVANT DE CONCLURE
----------------------------------------
Sans `sh` ou `jq`, ou si le capteur est introuvable, la garde REFUSE DE CONCLURE (code 2). Avant les
scénarios, elle vérifie que le faux `cscli` rend bien ce qui lui est demandé (épreuve du bac) : un
bouchon qui ne répond pas ferait passer tout capteur pour aveugle.

CE QU'ELLE NE TIENT PAS
-----------------------
· Les modes k3s (exec dans le DaemonSet agent) et Docker (`PLUME_CSCLI=docker exec …`) ne sont pas
  joués : seul le choix `PLUME_CSCLI` l'est. Le reste de la résolution est inchangé et partagé avec
  le `hub list` déjà livré.
· La forme réelle de `cscli metrics` est celle de l'échantillon relevé (v1.8) ; une forme future
  différente rend `illisible`, ce qui est un refus, jamais un vert.
· Elle ne juge pas la règle du démon qui consommerait `acq_verdict` : aucune n'est livrée ; l'alerte
  vient de l'aveu par le canal `de-collector-unavailable`.

Sortie : 0 tenu · 1 au moins un verdict ou un champ faux · 2 l'instrument REFUSE DE CONCLURE.
"""
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CAPTEUR = os.path.join(RACINE, "collectors", "crowdsec.sh")
LIB = os.path.join(RACINE, "collectors", "lib.sh")

OUTILS = ["sh", "jq", "date", "mktemp", "cat", "grep", "dirname", "basename", "cksum", "cut", "mv",
          "rm", "mkdir", "iconv", "head", "tail", "sed", "tr", "awk", "sync", "chmod", "printf", "env",
          "wc", "sort", "ls", "touch", "test", "["]

# Le faux `cscli` exige la commande EXACTE pour rendre l'échantillon. Le reste répond comme un vrai
# `cscli` répondrait, avec le code 0 : une autre section (`metrics show parsers -o json`) rend un
# objet SANS `acquisition`, un autre format (`-o human`, ou pas de `-o`) rend un tableau texte. Un
# capteur qui demanderait l'une ou l'autre ne serait ni sauvé par le repli ni servi par hasard : il
# lirait une réponse réelle qui ne porte pas l'acquisition, et rougirait.
FAUX_CSCLI = r"""#!/bin/sh
d="$FAKE_CS_DIR"
case "$*" in
  "alerts list --limit 0 -o json") printf '[]' ;;
  "hub list -o json") printf '{"scenarios":[{"name":"a"},{"name":"b"}]}' ;;
  "metrics show acquisition -o json") [ -f "$d/sans_show" ] && exit 1; [ -f "$d/metrics_ko" ] && exit 1; cat "$d/metrics" ;;
  "metrics -o json") [ -f "$d/metrics_ko" ] && exit 1; cat "$d/metrics" ;;
  "metrics show "*" -o json") printf '{"parsers":{}}' ;;
  metrics*) printf 'Acquisition Metrics:\n+--------+-------+\n| Source | Lines |\n+--------+-------+\n' ;;
  *) exit 1 ;;
esac
"""

S_A = "file:/var/log/containers/web-a.log"
S_OLD = "file:/var/log/containers/web-ancien.log"
S_NEW = "file:/var/log/containers/web-b.log"


def acq(d):
    return json.dumps({"acquisition": d})


# P10.32-k : les parts en liste blanche des échantillons sains restent SOUS le seuil par défaut du capteur
# (`surtout_liste_blanche`) — un échantillon où presque tout part en liste blanche n'est pas « sain ».
M1 = acq({S_A: {"reads": 1000, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 88},
          S_OLD: {"reads": 50, "parsed": 40, "unparsed": 10, "whitelisted": 4}})
M2 = acq({S_A: {"reads": 1300, "parsed": 1150, "unparsed": 150, "pour": 9, "whitelisted": 112},
          S_OLD: {"reads": 50, "parsed": 40, "unparsed": 10, "whitelisted": 4}})
M_RESTART = acq({S_NEW: {"reads": 30, "parsed": 25, "unparsed": 5, "pour": 1, "whitelisted": 20},
                 S_A: {"reads": 12, "parsed": 10, "unparsed": 2, "whitelisted": 9}})
M_ZERO = acq({S_A: {"reads": 0, "parsed": 0, "unparsed": 0, "whitelisted": 0}})
M1_NEUVE_VIDE = acq({S_A: {"reads": 1000, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 88},
                     S_OLD: {"reads": 50, "parsed": 40, "unparsed": 10, "whitelisted": 4},
                     S_NEW: {"reads": 0}})
M_NON_ANALYSE1 = acq({S_A: {"reads": 500, "unparsed": 500}})
M_NON_ANALYSE2 = acq({S_A: {"reads": 800, "unparsed": 800}})
M_A_ANALYSE = acq({S_A: {"reads": 1000, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 88}})
M_A_SANS_ANALYSE = acq({S_A: {"reads": 1200, "parsed": 900, "unparsed": 300, "pour": 7, "whitelisted": 88}})


M_WL1 = acq({S_A: {"reads": 100, "whitelisted": 100}})
M_WL2 = acq({S_A: {"reads": 200, "whitelisted": 200}})
M_DEUX_SOURCES1 = acq({S_A: {"reads": 1000, "parsed": 900, "unparsed": 100, "whitelisted": 88},
                       S_NEW: {"reads": 60, "unparsed": 60}})
M_DEUX_SOURCES2 = acq({S_A: {"reads": 1100, "parsed": 990, "unparsed": 110, "whitelisted": 96},
                       S_NEW: {"reads": 90, "unparsed": 90}})
M_A_SANS_ANALYSE_BIS = acq({S_A: {"reads": 1500, "parsed": 900, "unparsed": 600, "pour": 7, "whitelisted": 88}})


def source_p(i):
    return f"file:/var/log/containers/p{i:03d}.log"


def beaucoup(n, lisent):
    """`n` sources ; celles dont l'indice est dans `lisent` ont lu 5 lignes (4 analysées) de plus."""
    return acq({source_p(i):
                {"reads": 10 + (5 if i in lisent else 0), "parsed": 7 + (4 if i in lisent else 0),
                 "unparsed": 3 + (1 if i in lisent else 0), "pour": 1, "whitelisted": 2}
                for i in range(n)})

fautes = []


def refus(msg):
    print(f"::error::check_crowdsec_sensor_says_what_it_reads : REFUSE DE CONCLURE — {msg}")
    sys.exit(2)


def faute(scen, msg):
    fautes.append(f"[{scen}] {msg}")


def champs_declares(capteur):
    with open(capteur, encoding="utf-8") as f:
        for ligne in f:
            m = re.match(r"#\s*plume-emits:\s*fields=(\S*)", ligne)
            if m:
                return set(x for x in m.group(1).split(",") if x)
    return None


class Bac:
    def __init__(self, capteur):
        self.racine = tempfile.mkdtemp(prefix="plume-cs-acq-")
        self.bin = os.path.join(self.racine, "bin")
        os.mkdir(self.bin)
        for o in OUTILS:
            p = shutil.which(o)
            if p:
                os.symlink(p, os.path.join(self.bin, o))
        self.fake = os.path.join(self.racine, "fake-cscli")
        with open(self.fake, "w") as f:
            f.write(FAUX_CSCLI)
        os.chmod(self.fake, stat.S_IRWXU)
        self.capteur = capteur
        self.n = 0

    def nettoyer(self):
        shutil.rmtree(self.racine, ignore_errors=True)

    def scenario(self):
        self.n += 1
        d = os.path.join(self.racine, f"s{self.n}")
        os.makedirs(os.path.join(d, "etat"))
        os.makedirs(os.path.join(d, "cs"))
        return d

    def passage(self, d, metrics=None, ko=False, sans_show=False, etat=None):
        cs = os.path.join(d, "cs")
        for nom in ("metrics", "metrics_ko", "sans_show"):
            p = os.path.join(cs, nom)
            if os.path.exists(p):
                os.remove(p)
        if metrics is not None:
            with open(os.path.join(cs, "metrics"), "w") as f:
                f.write(metrics)
        if ko:
            open(os.path.join(cs, "metrics_ko"), "w").close()
        if sans_show:
            open(os.path.join(cs, "sans_show"), "w").close()
        spool = tempfile.mkdtemp(dir=d, prefix="spool-")
        env = {"PATH": self.bin, "PLUME_CSCLI": self.fake, "FAKE_CS_DIR": cs,
               "PLUME_SPOOL": spool, "PLUME_STATE": etat or os.path.join(d, "etat"),
               "PLUME_LIB": LIB, "LC_ALL": "C.UTF-8", "HOME": d}
        r = subprocess.run([os.path.join(self.bin, "sh"), self.capteur], env=env,
                           capture_output=True, text=True, timeout=60)
        evs = []
        for fp in sorted(glob.glob(os.path.join(spool, "*.json"))):
            with open(fp, encoding="utf-8") as f:
                txt = f.read()
            try:
                evs.extend(json.loads(txt).get("events", []))
            except ValueError:
                evs.append({"_illisible": os.path.basename(fp), "_texte": txt[:300]})
        return r, evs

    def etat(self, d):
        p = os.path.join(d, "etat", "crowdsec-acquisition.json")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return f.read()


def battement(scen, r, evs, declares):
    if r.returncode != 0:
        faute(scen, f"le capteur sort en {r.returncode} : {r.stderr.strip()[:300]}")
        return None
    bad = [e for e in evs if "_illisible" in e]
    if bad:
        faute(scen, f"enveloppe de spool qui n'est pas du JSON : {bad[0]}")
    hb = [e for e in evs if e.get("source") == "crowdsec" and e.get("category") == "health"]
    if len(hb) != 1:
        faute(scen, f"{len(hb)} battement(s) de santé, attendu 1")
        return None
    f = hb[0].get("fields") or {}
    hors = set(f) - declares
    if hors:
        faute(scen, f"champ(s) émis absents de l'en-tête plume-emits : {sorted(hors)}")
    return hb[0]


def aveux_acquisition(evs):
    return [e for e in evs if e.get("category") == "config"
            and "acquisition CrowdSec" in ((e.get("fields") or {}).get("detail") or "")]


def attendre_refus(scen, hb, evs, verdict, cause):
    f = hb["fields"]
    if f.get("acq_verdict") != verdict:
        faute(scen, f"acq_verdict={f.get('acq_verdict')!r}, attendu {verdict!r}")
    if hb.get("severity", 0) < 3:
        faute(scen, f"sévérité du battement {hb.get('severity')} : un refus de conclure la relève à 3 au moins")
    if f"ACQUISITION {verdict} :" not in (hb.get("message") or ""):
        faute(scen, f"le message du battement ne dit pas le refus d'acquisition : {hb.get('message')!r}")
    # Sur un refus, aucune source n'est « figée parmi d'autres qui lisent » : la liste reste vide.
    egal(scen, f, "acq_frozen_sources", [])
    av = aveux_acquisition(evs)
    if len(av) != 1:
        faute(scen, f"{len(av)} aveu(x) d'acquisition par le canal de couverture, attendu 1")
    else:
        fl = av[0]["fields"]
        if fl.get("collect_status") != "unavailable" or fl.get("reason") != "missing-source":
            faute(scen, f"aveu hors canal livré : {fl}")
        if f"({cause})" not in fl.get("detail", ""):
            faute(scen, f"cause attendue {cause!r} absente de l'aveu : {fl.get('detail')!r}")


def attendre_sans_refus(scen, hb, evs, verdict):
    f = hb["fields"]
    if f.get("acq_verdict") != verdict:
        faute(scen, f"acq_verdict={f.get('acq_verdict')!r}, attendu {verdict!r}")
    if hb.get("severity") != 0:
        faute(scen, f"sévérité {hb.get('severity')} sur un moteur sain qui lit, attendu 0")
    if aveux_acquisition(evs):
        faute(scen, "aveu d'acquisition émis alors que le moteur lit")
    if "ACQUISITION" in (hb.get("message") or ""):
        faute(scen, f"le message du battement annonce un refus d'acquisition sur un moteur qui lit : {hb.get('message')!r}")


def egal(scen, f, cle, attendu):
    if f.get(cle) != attendu:
        faute(scen, f"{cle}={f.get(cle)!r}, attendu {attendu!r}")


def detail_de(f, source):
    for x in f.get("acquisition") or []:
        if x.get("source") == source:
            return x
    return None


def lus_dans_etat(texte, source):
    """Compteur `reads` de `source` dans l'état local, None si l'état n'a pas la forme attendue."""
    try:
        e = json.loads(texte or "null")
    except ValueError:
        return None
    v = e.get(source) if isinstance(e, dict) else None
    return v.get("reads") if isinstance(v, dict) else None


def epreuve_du_bac(bac):
    d = bac.scenario()
    with open(os.path.join(d, "cs", "metrics"), "w") as f:
        f.write(M1)
    r = subprocess.run([bac.fake, "metrics", "show", "acquisition", "-o", "json"],
                       env={"PATH": bac.bin, "FAKE_CS_DIR": os.path.join(d, "cs")},
                       capture_output=True, text=True)
    if r.returncode != 0 or json.loads(r.stdout) != json.loads(M1):
        refus("le faux cscli ne rend pas les métriques demandées : le bac ne prouverait rien")
    for autre in (["metrics", "show", "parsers", "-o", "json"], ["metrics", "show", "acquisition", "-o", "human"],
                  ["metrics", "-o", "human"], ["metrics", "show", "acquisition"]):
        r = subprocess.run([bac.fake] + autre, env={"PATH": bac.bin, "FAKE_CS_DIR": os.path.join(d, "cs")},
                           capture_output=True, text=True)
        if r.returncode != 0 or "web-a.log" in r.stdout:
            refus(f"le faux cscli ne répond pas à `{' '.join(autre)}` comme un vrai (code 0, sans l'échantillon)")
    open(os.path.join(d, "cs", "metrics_ko"), "w").close()
    r = subprocess.run([bac.fake, "metrics", "-o", "json"],
                       env={"PATH": bac.bin, "FAKE_CS_DIR": os.path.join(d, "cs")},
                       capture_output=True, text=True)
    if r.returncode == 0:
        refus("le faux cscli ne sait pas échouer : le scénario « illisible » ne prouverait rien")


def main():
    capteur = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else CAPTEUR
    if not os.path.isfile(capteur) or not os.path.isfile(LIB):
        refus(f"capteur ou bibliothèque introuvable ({capteur})")
    for o in ("sh", "jq"):
        if not shutil.which(o):
            refus(f"`{o}` absent : le capteur ne peut pas être joué")
    declares = champs_declares(capteur)
    if not declares:
        refus("en-tête `# plume-emits: fields=` illisible")
    acq_cles = {"acq_verdict", "acq_sources", "acq_frozen_sources", "acq_counters_reset", "acquisition"}
    acq_cles |= {f"acq_{k}{x}" for k in ("reads", "parsed", "unparsed", "pour", "whitelisted") for x in ("", "_delta")}

    bac = Bac(capteur)
    try:
        epreuve_du_bac(bac)

        # 1) sain : premier passage puis lecture.
        s = "sain"
        d = bac.scenario()
        r, evs = bac.passage(d, M1)
        hb = battement(s + "/1", r, evs, declares)
        if hb:
            f = hb["fields"]
            manq = acq_cles - set(f)
            if manq:
                faute(s, f"champs d'acquisition absents du battement : {sorted(manq)}")
            attendre_sans_refus(s + "/1", hb, evs, "premier_passage")
            egal(s + "/1", f, "acq_sources", 2)
            egal(s + "/1", f, "acq_reads", 1050)
            egal(s + "/1", f, "acq_parsed", 940)
            egal(s + "/1", f, "acq_unparsed", 110)
            egal(s + "/1", f, "acq_pour", 7)
            egal(s + "/1", f, "acq_whitelisted", 92)
            for k in ("reads", "parsed", "unparsed", "pour", "whitelisted"):
                egal(s + "/1", f, f"acq_{k}_delta", -1)
            a = detail_de(f, S_A)
            att = {"source": S_A, "reads": 1000, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 88,
                   "reads_delta": -1, "parsed_delta": -1, "unparsed_delta": -1, "pour_delta": -1,
                   "whitelisted_delta": -1}
            if a != att:
                faute(s + "/1", f"détail par source faux pour {S_A} : {a}, attendu {att}")
        if bac.etat(d) is None:
            faute(s + "/1", "aucun état local posé après un passage publié")
        r, evs = bac.passage(d, M2)
        hb = battement(s + "/2", r, evs, declares)
        if hb:
            f = hb["fields"]
            attendre_sans_refus(s + "/2", hb, evs, "lit")
            egal(s + "/2", f, "acq_reads", 1350)
            egal(s + "/2", f, "acq_parsed", 1190)
            egal(s + "/2", f, "acq_unparsed", 160)
            egal(s + "/2", f, "acq_pour", 9)
            egal(s + "/2", f, "acq_whitelisted", 116)
            egal(s + "/2", f, "acq_reads_delta", 300)
            egal(s + "/2", f, "acq_parsed_delta", 250)
            egal(s + "/2", f, "acq_unparsed_delta", 50)
            egal(s + "/2", f, "acq_pour_delta", 2)
            egal(s + "/2", f, "acq_whitelisted_delta", 24)
            egal(s + "/2", f, "acq_counters_reset", False)
            egal(s + "/2", f, "acq_frozen_sources", [S_OLD])
            a = detail_de(f, S_A)
            att = {"source": S_A, "reads": 1300, "parsed": 1150, "unparsed": 150, "pour": 9, "whitelisted": 112,
                   "reads_delta": 300, "parsed_delta": 250, "unparsed_delta": 50, "pour_delta": 2,
                   "whitelisted_delta": 24}
            if a != att:
                faute(s + "/2", f"détail par source faux pour {S_A} : {a}, attendu {att}")
            o = detail_de(f, S_OLD)
            att = {"source": S_OLD, "reads": 50, "parsed": 40, "unparsed": 10, "pour": 0, "whitelisted": 4,
                   "reads_delta": 0, "parsed_delta": 0, "unparsed_delta": 0, "pour_delta": 0,
                   "whitelisted_delta": 0}
            if o != att:
                faute(s + "/2", f"détail par source faux pour {S_OLD} : {o}, attendu {att}")
            if len(f.get("acquisition") or []) != 2:
                faute(s + "/2", f"détail : {len(f.get('acquisition') or [])} entrées, attendu 2")
        if lus_dans_etat(bac.etat(d), S_A) != 1300:
            faute(s + "/2", f"état local non avancé après une lecture publiée : {bac.etat(d)!r}")

        # 2) figé : même lecture, plus une source neuve encore vide (l'état avancé la porterait).
        s = "fige"
        d = bac.scenario()
        bac.passage(d, M1)
        avant = bac.etat(d)
        if avant is None:
            faute(s, "aucun état posé au premier passage : la comparaison ne prouverait rien")
        r, evs = bac.passage(d, M1_NEUVE_VIDE)
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_refus(s, hb, evs, "aucune_lecture", "source_absente")
            egal(s, hb["fields"], "acq_reads_delta", 0)
        if bac.etat(d) != avant:
            faute(s, "l'état local a avancé sur un refus de conclure")

        # 3) aucune source, sur un état déjà posé (l'état avancé vaudrait `{}`).
        for nom, m in (("aucune_source/vide", acq({})), ("aucune_source/sans_cle", "{}")):
            d = bac.scenario()
            bac.passage(d, M1)
            avant = bac.etat(d)
            r, evs = bac.passage(d, m)
            hb = battement(nom, r, evs, declares)
            if hb:
                attendre_refus(nom, hb, evs, "aucune_source", "source_absente")
                egal(nom, hb["fields"], "acq_sources", 0)
            if avant is None or bac.etat(d) != avant:
                faute(nom, f"l'état local a avancé (ou n'était pas posé) sur un refus : {bac.etat(d)!r}")
            d = bac.scenario()
            bac.passage(d, m)
            if bac.etat(d) is not None:
                faute(nom + "/premier", "état posé au premier passage d'un refus")

        # 3 bis) lu mais rien analysé : au premier passage, puis sur l'intervalle.
        for nom, m0, m1 in (("aucune_analyse/premier", None, M_NON_ANALYSE1),
                            ("aucune_analyse/intervalle", M_A_ANALYSE, M_A_SANS_ANALYSE),
                            ("aucune_analyse/toujours", M_NON_ANALYSE1, M_NON_ANALYSE2)):
            d = bac.scenario()
            if m0 is not None:
                bac.passage(d, m0)
            avant = bac.etat(d)
            r, evs = bac.passage(d, m1)
            hb = battement(nom, r, evs, declares)
            if hb:
                attendre_refus(nom, hb, evs, "aucune_analyse", "forme_inconnue")
            if bac.etat(d) != avant:
                faute(nom, f"l'état local a avancé sur un refus : {bac.etat(d)!r}")

        # 3 ter) état précédent abîmé : premier passage, et l'état est réparé.
        for nom, contenu in (("etat_abime/vide", ""),
                             ("etat_abime/mauvaise_forme", '{"%s":5}' % S_A),
                             ("etat_abime/compteur_texte", '{"%s":{"reads":"x"}}' % S_A),
                             ("etat_abime/tableau", "[1,2]"),
                             ("etat_abime/pas_du_json", "garbage{")):
            d = bac.scenario()
            with open(os.path.join(d, "etat", "crowdsec-acquisition.json"), "w") as fh:
                fh.write(contenu)
            r, evs = bac.passage(d, M1)
            hb = battement(nom, r, evs, declares)
            if hb:
                attendre_sans_refus(nom, hb, evs, "premier_passage")
                egal(nom, hb["fields"], "acq_reads", 1050)
            if lus_dans_etat(bac.etat(d), S_A) != 1000:
                faute(nom, f"état abîmé non réparé par un passage publié : {bac.etat(d)!r}")

        # 3 quater) cent cinquante sources, dont une seule lit au second passage.
        s = "cent_cinquante_sources"
        d = bac.scenario()
        r, evs = bac.passage(d, beaucoup(150, ()))
        hb = battement(s + "/1", r, evs, declares)
        if hb:
            f = hb["fields"]
            egal(s + "/1", f, "acq_sources", 150)
            egal(s + "/1", f, "acq_reads", 1500)
            egal(s + "/1", f, "acq_parsed", 1050)
            egal(s + "/1", f, "acq_unparsed", 450)
            egal(s + "/1", f, "acq_pour", 150)
            egal(s + "/1", f, "acq_whitelisted", 300)
            if len(f.get("acquisition") or []) != 100:
                faute(s + "/1", f"détail de {len(f.get('acquisition') or [])} entrées, borne attendue 100")
        r, evs = bac.passage(d, beaucoup(150, {0}))
        hb = battement(s + "/2", r, evs, declares)
        if hb:
            f = hb["fields"]
            attendre_sans_refus(s + "/2", hb, evs, "lit")
            egal(s + "/2", f, "acq_sources", 150)
            egal(s + "/2", f, "acq_reads", 1505)
            egal(s + "/2", f, "acq_reads_delta", 5)
            egal(s + "/2", f, "acq_parsed_delta", 4)
            egal(s + "/2", f, "acq_unparsed_delta", 1)
            fz = f.get("acq_frozen_sources") or []
            if len(fz) != 100 or source_p(0) in fz:
                faute(s + "/2", f"acq_frozen_sources : {len(fz)} entrées (borne attendue 100, sans la source qui lit)")
            if len(f.get("acquisition") or []) != 100:
                faute(s + "/2", f"détail de {len(f.get('acquisition') or [])} entrées, borne attendue 100")

        # 3 quinquies) cent cinquante sources, et SEULE la 150e lit — hors du détail borné à 100 :
        # les différences totales la comptent quand même, sinon le moteur passerait pour aveugle.
        s = "cent_cinquante_sources/derniere"
        d = bac.scenario()
        bac.passage(d, beaucoup(150, ()))
        r, evs = bac.passage(d, beaucoup(150, {149}))
        hb = battement(s, r, evs, declares)
        if hb:
            f = hb["fields"]
            attendre_sans_refus(s, hb, evs, "lit")
            egal(s, f, "acq_reads_delta", 5)
            egal(s, f, "acq_parsed_delta", 4)
            egal(s, f, "acq_unparsed_delta", 1)
            fz = f.get("acq_frozen_sources") or []
            if len(fz) != 100 or source_p(149) in fz:
                faute(s, f"acq_frozen_sources : {len(fz)} entrées (borne attendue 100, sans la source qui lit)")

        # 3 sexies) une source lit sans rien analyser, une autre analyse : `lit`, et la première
        # n'est PAS nommée figée — elle lit ; son parseur cassé se voit dans son détail.
        s = "une_source_lit_sans_analyse"
        d = bac.scenario()
        bac.passage(d, M_DEUX_SOURCES1)
        r, evs = bac.passage(d, M_DEUX_SOURCES2)
        hb = battement(s, r, evs, declares)
        if hb:
            f = hb["fields"]
            attendre_sans_refus(s, hb, evs, "lit")
            egal(s, f, "acq_frozen_sources", [])
            n = detail_de(f, S_NEW) or {}
            if (n.get("reads_delta"), n.get("unparsed_delta"), n.get("parsed_delta")) != (30, 30, 0):
                faute(s, f"détail de la source non analysée faux : {n}")

        # 3 septies) lignes lues, aucune analysée MAIS écartées par liste blanche : elles ont atteint
        # l'analyse, ce n'est pas `aucune_analyse` ; et rien n'atteint les scénarios, ce n'est pas `lit`
        # non plus (`P10.32-k`) : `tout_en_liste_blanche`, un refus qui n'avance pas l'état — deux passages.
        s = "liste_blanche_sans_analyse"
        d = bac.scenario()
        r, evs = bac.passage(d, M_WL1)
        hb = battement(s + "/1", r, evs, declares)
        if hb:
            attendre_refus(s + "/1", hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        r, evs = bac.passage(d, M_WL2)
        hb = battement(s + "/2", r, evs, declares)
        if hb:
            attendre_refus(s + "/2", hb, evs, "tout_en_liste_blanche", "forme_inconnue")
            egal(s + "/2", hb["fields"], "acq_whitelisted", 200)
        if bac.etat(d) is not None:
            faute(s, f"état posé sur un refus de liste blanche : {bac.etat(d)!r}")

        # 3 octies) état impossible à poser (répertoire d'état sous un FICHIER : `mktemp` échoue, même
        # pour root) : le battement part, la lecture est dite, et l'échec de l'état est AVOUÉ.
        s = "etat_non_inscriptible"
        d = bac.scenario()
        bouchon = os.path.join(d, "bouchon")
        open(bouchon, "w").close()
        r, evs = bac.passage(d, M1, etat=os.path.join(bouchon, "etat"))
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_sans_refus(s, hb, evs, "premier_passage")
            av = [e for e in evs if e.get("category") == "config"
                  and "etat/acquisition" in ((e.get("fields") or {}).get("detail") or "")]
            if len(av) != 1:
                faute(s, f"{len(av)} aveu(x) d'état d'acquisition non posé, attendu 1")

        # 3 nonies) refus qui se répète sur un état figé : les lignes lues GRANDISSENT d'un passage à
        # l'autre (l'état n'avance pas), la clé de dédoublonnage de l'aveu, elle, ne doit pas changer —
        # sinon la dédup horaire du canal ne tient plus. Seule l'empreinte est comparée (le seau
        # horaire peut tourner entre deux passages).
        s = "aucune_analyse/cle_stable"
        d = bac.scenario()
        bac.passage(d, M_A_ANALYSE)
        cles = []
        for m in (M_A_SANS_ANALYSE, M_A_SANS_ANALYSE_BIS):
            r, evs = bac.passage(d, m)
            hb = battement(s, r, evs, declares)
            av = aveux_acquisition(evs)
            if hb and len(av) == 1:
                cles.append(av[0].get("dedup", "").rsplit("-", 1)[0])
        if len(cles) != 2 or not cles[0] or cles[0] != cles[1]:
            faute(s, f"clé de dédoublonnage de l'aveu instable d'un passage à l'autre : {cles}")

        # 3 decies) la clé stable DISCRIMINE : deux verdicts ou deux causes différents dans la même heure
        # ne prennent pas la même clé — sinon le central, qui garde le premier aveu de l'heure, tairait
        # le second refus.
        s = "aveux_distincts/cle"
        par_refus = {}
        for nom, avant_m, kw in (("aucune_analyse", M_A_ANALYSE, {"metrics": M_A_SANS_ANALYSE}),
                                 ("aucune_lecture", M1, {"metrics": M1}),
                                 ("illisible/echec", M1, {"metrics": M1, "ko": True}),
                                 ("illisible/forme", M1, {"metrics": "level=error msg=boom\n"})):
            d = bac.scenario()
            bac.passage(d, avant_m)
            r, evs = bac.passage(d, **kw)
            av = aveux_acquisition(evs)
            if len(av) == 1:
                par_refus[nom] = av[0].get("dedup", "").rsplit("-", 1)[0]
        if len(par_refus) != 4 or len(set(par_refus.values())) != 4:
            faute(s, f"clés de dédoublonnage non discriminantes entre refus distincts : {par_refus}")

        # 4) illisible : échec de la commande, puis sortie qui n'est pas du JSON.
        for nom, kw, cause in (("illisible/echec", {"metrics": M1, "ko": True}, "source_illisible"),
                               ("illisible/forme", {"metrics": "level=error msg=boom\n"}, "forme_inconnue"),
                               ("illisible/vide", {"metrics": ""}, "forme_inconnue"),
                               ("illisible/compteur", {"metrics": acq({S_A: {"reads": "x"}})}, "forme_inconnue")):
            d = bac.scenario()
            bac.passage(d, M1)
            avant = bac.etat(d)
            r, evs = bac.passage(d, **kw)
            hb = battement(nom, r, evs, declares)
            if hb:
                attendre_refus(nom, hb, evs, "illisible", cause)
                egal(nom, hb["fields"], "acq_reads", -1)
                egal(nom, hb["fields"], "acq_reads_delta", -1)
            if bac.etat(d) != avant:
                faute(nom, "l'état local a avancé sur une lecture illisible")

        # 5) redémarrage de l'agent : compteurs qui diminuent + source neuve.
        s = "redemarrage"
        d = bac.scenario()
        bac.passage(d, M2)
        r, evs = bac.passage(d, M_RESTART)
        hb = battement(s, r, evs, declares)
        if hb:
            f = hb["fields"]
            attendre_sans_refus(s, hb, evs, "lit")
            egal(s, f, "acq_counters_reset", True)
            egal(s, f, "acq_reads_delta", 42)
            egal(s, f, "acq_parsed_delta", 35)
            negatifs = [k for k, v in f.items() if k.endswith("_delta") and isinstance(v, int) and v < 0]
            negatifs += [f"{x.get('source')}.{k}" for x in f.get("acquisition") or []
                         for k, v in x.items() if k.endswith("_delta") and isinstance(v, int) and v < 0]
            if negatifs:
                faute(s, f"différence négative après un redémarrage : {negatifs}")

        # 6) rien lu depuis le démarrage, au premier passage.
        s = "zero_au_premier_passage"
        d = bac.scenario()
        r, evs = bac.passage(d, M_ZERO)
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_refus(s, hb, evs, "aucune_lecture", "source_absente")
        if bac.etat(d) is not None:
            faute(s, "état posé au premier passage d'un refus")

        # 7) cscli sans `metrics show`.
        s = "cscli_ancien"
        d = bac.scenario()
        r, evs = bac.passage(d, M1, sans_show=True)
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_sans_refus(s, hb, evs, "premier_passage")
            egal(s, hb["fields"], "acq_reads", 1050)
    finally:
        bac.nettoyer()

    if fautes:
        for x in fautes:
            print(f"::error::{x}")
        print(f"check_crowdsec_sensor_says_what_it_reads : {len(fautes)} faute(s), capteur {os.path.relpath(capteur, RACINE)}")
        return 1
    print(f"check_crowdsec_sensor_says_what_it_reads : tenu — {bac.n - 1} scénarios joués sur {os.path.relpath(capteur, RACINE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
