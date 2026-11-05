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
  · premier passage, une source à zéro — aucune ligne lue depuis le démarrage de l'agent alors que les
                       autres lisent : nommée dans `acq_frozen_sources` dès le premier passage, sans refus ;
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
  · liste blanche, prolongation de `P10.32-k` (mesuré en production le 2026-11-04) — RÉPARTITION par nœud de
                       liste blanche (`metrics show whitelists -o json`, forme des sources CrowdSec v1.6.8/v1.7.0)
                       nommée sur la fenêtre, contre un état séparé (`crowdsec-whitelists.json`) posé AVEC l'état
                       d'acquisition ; une liste de session qui écarte des lignes donne la cause « vraies adresses »,
                       jamais la cause mandataire, qui n'est dite que si tout part dans `crowdsecurity/whitelists` ;
                       répartition vide, en échec, `null`, non numérique ou mal formée : « répartition inconnue »,
                       aucune cause affirmée ; redémarrage (valeur courante) et nœud neuf (depuis zéro) ; un passage
                       qui avance sans répartition lisible écrit `null`, le suivant repart des totaux et le dit.
                       DURÉE : sous `PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES` (défaut 24),
                       `en_liste_blanche_sous_le_seuil`, sévérité 1, aucun aveu, durée et seuil dits, AUCUN des trois
                       états n'avance ; horodatage vieilli de 25 h : refus, aveu, durée dite, clé de dédoublonnage
                       identique à 25 h et à 30 h ; réglage 0 : refus immédiat ; réglage illisible : repli dit, défaut
                       appliqué ; horodatage absent ou futur : posé au passage qui le constate, dit tel ; horodatage
                       qui AVANCE sur tout passage qui lit (lit -> vieilli -> lit -> tout : sous le seuil, 0 h).
                       Les témoins du CHOIX de la cause : nom EXACT de la liste privée (une liste du hub à adresses
                       publiques n'est pas elle), nœud à différence nulle GARDÉ dans l'état, morceau mal formé posé
                       à côté d'un nœud valide (l'avaler laisserait une répartition partielle affirmer la cause
                       mandataire), dix plus GROS nœuds nommés et noms coupés à 80, état de listes blanches mal formé
                       rejeté, repli `metrics -o json` quand `show whitelists` n'a pas de section, variante de cause
                       dans la clé de dédoublonnage, compteur négatif mal formé, nom qui CONTIENT celui de la liste
                       privée sans l'être. La BASE de la répartition est jugée sur son libellé, dans les deux sens
                       (« sur la fenêtre » / « depuis le démarrage de l'agent »), au battement et à l'aveu ; « aucun
                       trafic anonyme n'a atteint l'origine » est exigé sous le seuil comme au refus. ÉTAT NON
                       INSCRIPTIBLE : l'horodatage ne pouvant se poser, refus sans attendre le seuil, dit, et
                       `etat/horodatage` avoué ; un faux `mktemp` ciblé fait échouer l'horodatage ou l'état des
                       listes blanches sur un passage qui lit : chacun avoué sous son nom.
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
  "metrics show whitelists -o json") [ -f "$d/wl_ko" ] && exit 1; if [ -f "$d/wl" ]; then cat "$d/wl"; else printf '{"whitelists":{}}'; fi ;;
  "metrics -o json") [ -f "$d/metrics_ko" ] && exit 1; if [ -f "$d/metrics_tout" ]; then cat "$d/metrics_tout"; else cat "$d/metrics"; fi ;;
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
# La borne `reads == 0` du premier passage : une source qui a lu UNE ligne depuis le démarrage de l'agent lit,
# elle n'est pas figée (un `<= 1` à sa place passait vert faute d'une telle source).
S_UNE = "file:/var/log/containers/web-une-ligne.log"
M1_NEUVE_VIDE_ET_UNE_LIGNE = acq({S_A: {"reads": 1000, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 88},
                                  S_UNE: {"reads": 1, "parsed": 1},
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

    def passage(self, d, metrics=None, ko=False, sans_show=False, etat=None, wl=None, wl_ko=False, env_sup=None,
                metrics_tout=None):
        cs = os.path.join(d, "cs")
        for nom in ("metrics", "metrics_ko", "sans_show", "wl", "wl_ko", "metrics_tout"):
            p = os.path.join(cs, nom)
            if os.path.exists(p):
                os.remove(p)
        if metrics is not None:
            with open(os.path.join(cs, "metrics"), "w") as f:
                f.write(metrics)
        if wl is not None:
            with open(os.path.join(cs, "wl"), "w") as f:
                f.write(wl)
        if metrics_tout is not None:
            with open(os.path.join(cs, "metrics_tout"), "w") as f:
                f.write(metrics_tout)
        if ko:
            open(os.path.join(cs, "metrics_ko"), "w").close()
        if wl_ko:
            open(os.path.join(cs, "wl_ko"), "w").close()
        if sans_show:
            open(os.path.join(cs, "sans_show"), "w").close()
        spool = tempfile.mkdtemp(dir=d, prefix="spool-")
        env = {"PATH": self.bin, "PLUME_CSCLI": self.fake, "FAKE_CS_DIR": cs,
               "PLUME_SPOOL": spool, "PLUME_STATE": etat or os.path.join(d, "etat"),
               "PLUME_LIB": LIB, "LC_ALL": "C.UTF-8", "HOME": d}
        env.update(env_sup or {})
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

    def etat(self, d, nom="crowdsec-acquisition.json"):
        p = os.path.join(d, "etat", nom)
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return f.read()

    def poser(self, d, nom, texte):
        with open(os.path.join(d, "etat", nom), "w") as f:
            f.write(texte)


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


# --- P10.32-k, prolongation (mesuré en production le 2026-11-04) -------------------------------------------
# Répartition par liste blanche (`cscli metrics show whitelists -o json`, forme lue dans les sources CrowdSec
# v1.6.8/v1.7.0 : nœud -> raison -> {hits, whitelisted}) et durée sans aucune ligne aux scénarios.
IMMEDIAT = {"PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES": "0"}
PRIVEE = "crowdsecurity/whitelists"
SSO = "exemple/session-sso"
WL_ETAT = "crowdsec-whitelists.json"
TS_ETAT = "crowdsec-scenarios-atteints.ts"
PHRASE_MANDATAIRE = "l'adresse cliente que CrowdSec lit est privée"
PHRASE_MANDATAIRE_A = "l'adresse cliente que CrowdSec lit est privee"
PHRASE_VRAIES = "le moteur lit les vraies adresses"
# Le LIBELLÉ de la répartition, pas un morceau qu'une autre phrase porterait (la cause « vraies adresses » finit par
# « sur la fenêtre ») : la base est jugée dans les deux sens.
REP_FENETRE = "répartition des lignes écartées sur la fenêtre :"
REP_DEMARRAGE = "répartition des lignes écartées depuis le démarrage de l'agent :"
REP_FENETRE_A = "repartition des lignes ecartees sur la fenetre :"
REP_DEMARRAGE_A = "repartition des lignes ecartees depuis le demarrage de l'agent :"
RIEN_D_ANONYME = "aucun trafic anonyme n'a atteint l'origine sur la fenêtre"
RIEN_D_ANONYME_A = "aucun trafic anonyme n'a atteint l'origine sur la fenetre"


def base(scen, msg, voulue):
    """La répartition dit SA base : `voulue` présente, l'autre absente."""
    oui, non = (REP_FENETRE, REP_DEMARRAGE) if voulue == "fenetre" else (REP_DEMARRAGE, REP_FENETRE)
    if oui not in msg or non in msg:
        faute(scen, f"base de la répartition : {oui!r} attendu, {non!r} interdit : {msg!r}")


def wl(d):
    return json.dumps({"whitelists": {nom: {"raison": {"hits": n + 3, "whitelisted": n}} for nom, n in d.items()}})


# Un passage où des lignes atteignent les scénarios (l'état avance), puis un passage tout en liste blanche :
# 100 lignes de plus, toutes écartées, aucune analysée hors liste blanche, aucune versée (forme disjointe).
M_LB_AVANT = acq({S_A: {"reads": 1000, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 88}})
M_LB_TOUT = acq({S_A: {"reads": 1100, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 188}})
M_LB_TOUT_BIS = acq({S_A: {"reads": 1150, "parsed": 900, "unparsed": 100, "pour": 7, "whitelisted": 238}})
M_LB_REDEMARRE = acq({S_A: {"reads": 50, "whitelisted": 50}})
# Après M_LB_AVANT : un passage qui LIT (100 analysées, 2 en liste blanche, 2 versées), puis 100 lignes toutes
# écartées.
M_LB_LIT = acq({S_A: {"reads": 1100, "parsed": 1000, "unparsed": 100, "pour": 9, "whitelisted": 90}})
M_LB_TOUT_APRES_LIT = acq({S_A: {"reads": 1200, "parsed": 1000, "unparsed": 100, "pour": 9, "whitelisted": 190}})


def aveux_reglage(evs, cle):
    return [e for e in evs if e.get("category") == "config"
            and (e.get("fields") or {}).get("collect_status") == "fallback"
            and cle in ((e.get("fields") or {}).get("detail") or "")]


def cle_aveu(evs):
    av = aveux_acquisition(evs)
    return av[0].get("dedup", "").rsplit("-", 1)[0] if len(av) == 1 else None


def sous_le_seuil(scen, hb, evs, *morceaux):
    """Sous le seuil de durée : verdict nommé, sévérité 1, AUCUN aveu, la durée et le seuil dits."""
    f = hb["fields"]
    egal(scen, f, "acq_verdict", "en_liste_blanche_sous_le_seuil")
    if hb.get("severity") != 1:
        faute(scen, f"sévérité {hb.get('severity')} sous le seuil de durée, attendu 1")
    if aveux_acquisition(evs):
        faute(scen, "aveu d'acquisition émis sous le seuil de durée")
    msg = hb.get("message") or ""
    for m in ("acquisition en_liste_blanche_sous_le_seuil :", "seuil 24 h") + morceaux:
        if m not in msg:
            faute(scen, f"{m!r} absent du message : {msg!r}")
    if "ACQUISITION" in msg:
        faute(scen, f"le message annonce un refus sous le seuil : {msg!r}")


def prolongation(bac, declares):
    maintenant = int(__import__("time").time())

    # P1 — répartition sur la fenêtre, une liste de session a écarté des lignes : la cause est « vraies adresses »,
    # jamais la cause mandataire ; sous le seuil (horodatage posé au passage qui avance) : sévérité 1, pas d'aveu,
    # aucun des trois états n'avance.
    s = "prolongation/vraies_adresses/sous_le_seuil"
    d = bac.scenario()
    r, evs = bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}))
    if json.loads(bac.etat(d, WL_ETAT) or "null") != {PRIVEE: 80, SSO: 8}:
        faute(s, f"état des listes blanches non posé avec l'acquisition : {bac.etat(d, WL_ETAT)!r}")
    t0 = bac.etat(d, TS_ETAT)
    if not t0 or not t0.isdigit() or abs(int(t0) - maintenant) > 120:
        faute(s, f"horodatage non posé avec l'état d'acquisition : {t0!r}")
    avant = (bac.etat(d), bac.etat(d, WL_ETAT), bac.etat(d, TS_ETAT))
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 170, SSO: 18}))
    hb = battement(s, r, evs, declares)
    if hb:
        sous_le_seuil(s, hb, evs, f"{PRIVEE} : 90", f"{SSO} : 10", PHRASE_VRAIES, RIEN_D_ANONYME, "0 h 0")
        base(s, hb.get("message") or "", "fenetre")
        if PHRASE_MANDATAIRE in (hb.get("message") or ""):
            faute(s, "cause mandataire dite alors qu'une liste de session a écarté des lignes")
    if (bac.etat(d), bac.etat(d, WL_ETAT), bac.etat(d, TS_ETAT)) != avant:
        faute(s, "un état a avancé sous le seuil de durée : la fenêtre ne courrait plus")

    # P2 — au-delà du seuil (horodatage vieilli de 25 h) : refus, aveu, cause « vraies adresses », durée dite ;
    # la clé de dédoublonnage ne porte pas la durée (25 h puis 30 h : même clé) ; état non avancé.
    s = "prolongation/vraies_adresses/au_dela_du_seuil"
    bac.poser(d, TS_ETAT, str(maintenant - 25 * 3600))
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 170, SSO: 18}))
    hb = battement(s, r, evs, declares)
    cles = []
    if hb:
        attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        base(s, hb.get("message") or "", "fenetre")
        for m in (f"{PRIVEE} : 90", f"{SSO} : 10", PHRASE_VRAIES, RIEN_D_ANONYME, "25 h", "seuil 24 h"):
            if m not in (hb.get("message") or ""):
                faute(s, f"{m!r} absent du message du refus : {hb.get('message')!r}")
        av = aveux_acquisition(evs)
        if len(av) == 1:
            det = av[0]["fields"].get("detail") or ""
            for m in (f"{PRIVEE} : 90", f"{SSO} : 10", PHRASE_VRAIES, RIEN_D_ANONYME_A, REP_FENETRE_A, "25 h"):
                if m not in det:
                    faute(s, f"{m!r} absent du détail de l'aveu : {det!r}")
            if PHRASE_MANDATAIRE_A in det:
                faute(s, f"cause mandataire dans l'aveu malgré une liste de session : {det!r}")
            if not det.isascii():
                faute(s, f"détail d'aveu hors ASCII : {det!r}")
        cles.append(cle_aveu(evs))
    bac.poser(d, TS_ETAT, str(maintenant - 30 * 3600))
    r, evs = bac.passage(d, M_LB_TOUT_BIS, wl=wl({PRIVEE: 210, SSO: 28}))
    cles.append(cle_aveu(evs))
    if None in cles or cles[0] != cles[1]:
        faute(s, f"clé de dédoublonnage qui suit la durée ou les comptes : {cles}")
    if (bac.etat(d), bac.etat(d, WL_ETAT)) != avant[:2]:
        faute(s, "état avancé sur un refus de liste blanche")

    # P3 — toutes les lignes écartées par la liste PRIVÉE : la cause mandataire, et seulement elle.
    for nom, env, refus_attendu in (("prolongation/mandataire/sous_le_seuil", None, False),
                                    ("prolongation/mandataire/reglage_zero", IMMEDIAT, True)):
        d = bac.scenario()
        bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}), env_sup=env)
        r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 180, SSO: 8}), env_sup=env)
        hb = battement(nom, r, evs, declares)
        if hb:
            msg = hb.get("message") or ""
            if refus_attendu:
                attendre_refus(nom, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
                det = (aveux_acquisition(evs) or [{}])[0].get("fields", {}).get("detail", "")
                if PHRASE_MANDATAIRE_A not in det or f"{PRIVEE} : 100" not in det:
                    faute(nom, f"cause mandataire ou répartition absente de l'aveu : {det!r}")
            else:
                sous_le_seuil(nom, hb, evs, f"{PRIVEE} : 100")
            if PHRASE_MANDATAIRE not in msg or PHRASE_VRAIES in msg or SSO in msg:
                faute(nom, f"tout part dans la liste privée : cause mandataire attendue, seule : {msg!r}")

    # P4 — répartition illisible (section absente, en échec, compteur non numérique, nœud mal formé, raison mal
    # formée) : « répartition inconnue », ni cause mandataire ni « vraies adresses ». Le morceau mal formé est
    # posé À CÔTÉ d'un nœud valide (la liste privée) : une lecture qui l'avalerait (compteur ramené à 0, nœud ou
    # raison sautés) garderait le seul nœud privé et affirmerait la cause mandataire sur une répartition partielle.
    bon = {"r": {"hits": 183, "whitelisted": 180}}
    for nom, kw in (("prolongation/inconnue/vide", {"wl": json.dumps({"whitelists": {}})}),
                    ("prolongation/inconnue/echec", {"wl_ko": True}),
                    ("prolongation/inconnue/null", {"wl": json.dumps({"whitelists": None})}),
                    ("prolongation/inconnue/compteur",
                     {"wl": json.dumps({"whitelists": {PRIVEE: bon, SSO: {"r": {"whitelisted": "x"}}}})}),
                    # compteur NÉGATIF : il n'est pas « en dessous de l'état » (redémarrage), il est mal formé ; pris
                    # pour tel, sa différence négative serait écartée et le seul nœud privé affirmerait la cause.
                    ("prolongation/inconnue/negatif",
                     {"wl": json.dumps({"whitelists": {PRIVEE: bon, SSO: {"r": {"hits": 1, "whitelisted": -5}}}})}),
                    ("prolongation/inconnue/forme", {"wl": json.dumps({"whitelists": {PRIVEE: bon, SSO: 5}})}),
                    ("prolongation/inconnue/raison", {"wl": json.dumps({"whitelists": {PRIVEE: bon, SSO: {"r": 5}}})})):
        d = bac.scenario()
        bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}))
        r, evs = bac.passage(d, M_LB_TOUT, env_sup=IMMEDIAT, **kw)
        hb = battement(nom, r, evs, declares)
        if hb:
            attendre_refus(nom, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
            msg = hb.get("message") or ""
            det = (aveux_acquisition(evs) or [{}])[0].get("fields", {}).get("detail", "")
            if "répartition inconnue" not in msg or "repartition inconnue" not in det:
                faute(nom, f"répartition illisible non dite : {msg!r}")
            if PHRASE_MANDATAIRE in msg or PHRASE_MANDATAIRE_A in det or PHRASE_VRAIES in msg:
                faute(nom, f"cause affirmée sur une répartition illisible : {msg!r}")

    # P5 — mêmes règles que l'acquisition : compteur qui baisse = redémarrage (valeur courante), nœud neuf à zéro.
    s = "prolongation/redemarrage_et_noeud_neuf"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}))
    r, evs = bac.passage(d, M_LB_REDEMARRE, wl=wl({PRIVEE: 30, SSO: 20, "exemple/neuve": 5}), env_sup=IMMEDIAT)
    hb = battement(s, r, evs, declares)
    if hb:
        attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        for m in (f"{PRIVEE} : 30", f"{SSO} : 12", "exemple/neuve : 5"):
            if m not in (hb.get("message") or ""):
                faute(s, f"{m!r} absent : {hb.get('message')!r}")

    # P6 — premier passage, aucun état ni horodatage : répartition depuis le démarrage de l'agent, horodatage
    # POSÉ à ce passage (et dit), sous le seuil ; l'état d'acquisition reste absent.
    s = "prolongation/horodatage_absent"
    d = bac.scenario()
    r, evs = bac.passage(d, M_WL1, wl=wl({PRIVEE: 100}))
    hb = battement(s, r, evs, declares)
    if hb:
        sous_le_seuil(s, hb, evs, "horodatage absent", f"{PRIVEE} : 100")
        base(s, hb.get("message") or "", "demarrage")
    t = bac.etat(d, TS_ETAT)
    if not t or not t.isdigit() or abs(int(t) - maintenant) > 120:
        faute(s, f"horodatage absent non posé au passage qui le constate : {t!r}")
    if bac.etat(d) is not None or bac.etat(d, WL_ETAT) is not None:
        faute(s, "état d'acquisition ou de listes blanches posé sous le seuil")
    # ... et un horodatage dans le futur (horloge revenue en arrière) est traité comme absent, re-posé.
    s = "prolongation/horodatage_futur"
    d = bac.scenario()
    bac.poser(d, TS_ETAT, str(maintenant + 10 * 3600))
    r, evs = bac.passage(d, M_WL1, wl=wl({PRIVEE: 100}))
    hb = battement(s, r, evs, declares)
    if hb:
        sous_le_seuil(s, hb, evs, "horodatage absent")
    t = bac.etat(d, TS_ETAT)
    if not t or not t.isdigit() or int(t) > maintenant + 120:
        faute(s, f"horodatage futur gardé : {t!r}")

    # P7 — réglage illisible : repli sur 24 dit (`fallback`), et le défaut s'applique (sous le seuil).
    s = "prolongation/reglage_illisible"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80}))
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 180}),
                         env_sup={"PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES": "un jour"})
    hb = battement(s, r, evs, declares)
    if hb:
        sous_le_seuil(s, hb, evs)
    if len(aveux_reglage(evs, "PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES")) != 1:
        faute(s, "réglage de durée illisible non avoué (`fallback`)")

    # P8 — un passage qui avance avec une répartition illisible écrit `null` : le passage suivant repart des
    # totaux depuis le démarrage, il n'attribue pas à la fenêtre des lignes d'avant elle.
    s = "prolongation/avance_sans_repartition"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl_ko=True)
    if bac.etat(d) is None or (bac.etat(d, WL_ETAT) or "").strip() != "null":
        faute(s, f"état des listes blanches attendu `null` après une répartition illisible : {bac.etat(d, WL_ETAT)!r}")
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 180}))
    hb = battement(s, r, evs, declares)
    if hb:
        sous_le_seuil(s, hb, evs, f"{PRIVEE} : 180")
        base(s, hb.get("message") or "", "demarrage")

    # P9 — l'horodatage AVANCE à chaque passage qui avance, même s'il existe déjà : lit -> horodatage vieilli de
    # 25 h -> lit -> tout. La durée part du DERNIER passage qui a atteint les scénarios : sous le seuil, 0 h.
    # (Un horodatage posé seulement s'il manque ferait partir la durée de l'installation : 24 h après, chaque
    # `tout_en_liste_blanche` refuserait de nouveau à chaque passage.)
    s = "prolongation/horodatage_avance_sur_un_passage_qui_lit"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}))
    bac.poser(d, TS_ETAT, str(maintenant - 25 * 3600))
    bac.passage(d, M_LB_LIT, wl=wl({PRIVEE: 82, SSO: 8}))
    t = bac.etat(d, TS_ETAT)
    if not t or not t.isdigit() or abs(int(t) - maintenant) > 120:
        faute(s, f"horodatage non avancé par un passage qui lit : {t!r} (maintenant {maintenant})")
    r, evs = bac.passage(d, M_LB_TOUT_APRES_LIT, wl=wl({PRIVEE: 182, SSO: 8}))
    hb = battement(s, r, evs, declares)
    if hb:
        sous_le_seuil(s, hb, evs, "0 h 0")

    # P10 — le NOM EXACT de la liste privée, pas un préfixe : une liste du hub `crowdsecurity/` qui porte des
    # adresses PUBLIQUES (`crowdsecurity/cdn-whitelist`) prouve que les vraies adresses sont lues.
    # ... ni un nom qui CONTIENT celui de la liste privée sans l'être (égalité, pas inclusion), ni un nom qui
    # COMMENCE ou FINIT par lui (`startswith` / `endswith` ne sont pas l'égalité non plus), ni un nom qui ne
    # diffère que par la CASSE (les noms de parseurs CrowdSec sont sensibles à la casse : `ascii_downcase` non plus).
    cle_vraies = None
    for s, cdn in (("prolongation/liste_du_hub_publique", "crowdsecurity/cdn-whitelist"),
                   ("prolongation/nom_qui_contient_la_liste_privee", "exemple/crowdsecurity/whitelists-publiques"),
                   ("prolongation/nom_qui_commence_par_la_liste_privee", "crowdsecurity/whitelists-publiques"),
                   ("prolongation/nom_qui_finit_par_la_liste_privee", "exemple/crowdsecurity/whitelists"),
                   ("prolongation/nom_qui_differe_de_la_liste_privee_par_la_casse", "CrowdSecurity/Whitelists")):
        d = bac.scenario()
        bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, cdn: 8}), env_sup=IMMEDIAT)
        r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 170, cdn: 18}), env_sup=IMMEDIAT)
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
            msg = hb.get("message") or ""
            if f"{cdn} : 10" not in msg or PHRASE_VRAIES not in msg or PHRASE_MANDATAIRE in msg:
                faute(s, f"liste autre que la liste privée prise pour elle : {msg!r}")
            if cle_vraies is None:
                cle_vraies = cle_aveu(evs)

    # P11 — un nœud dont la différence est NULLE sur un passage qui avance reste dans l'état : au passage suivant,
    # il ne compte que ce qu'il a écarté sur la fenêtre (rien), il n'est pas recompté en entier.
    s = "prolongation/noeud_nul_garde_dans_l_etat"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}), env_sup=IMMEDIAT)
    bac.passage(d, M_LB_LIT, wl=wl({PRIVEE: 82, SSO: 8}), env_sup=IMMEDIAT)
    if json.loads(bac.etat(d, WL_ETAT) or "null") != {PRIVEE: 82, SSO: 8}:
        faute(s, f"état des listes blanches qui perd un nœud à différence nulle : {bac.etat(d, WL_ETAT)!r}")
    r, evs = bac.passage(d, M_LB_TOUT_APRES_LIT, wl=wl({PRIVEE: 182, SSO: 8}), env_sup=IMMEDIAT)
    hb = battement(s, r, evs, declares)
    cle_mandataire = None
    if hb:
        attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        msg = hb.get("message") or ""
        if f"{PRIVEE} : 100" not in msg or PHRASE_MANDATAIRE not in msg or SSO in msg or PHRASE_VRAIES in msg:
            faute(s, f"nœud sans ligne écartée sur la fenêtre recompté : {msg!r}")
        cle_mandataire = cle_aveu(evs)
    # ... et la variante de cause est dans la clé de dédoublonnage : une cause qui change dans l'heure est un
    # nouvel aveu (même verdict, même cause d'acquisition, variante différente).
    if cle_vraies is None or cle_mandataire is None or cle_vraies == cle_mandataire:
        faute(s, f"clé de dédoublonnage aveugle à la variante de cause : {cle_vraies!r} / {cle_mandataire!r}")

    # P11 bis — un compteur `whitelisted` à ZÉRO est un compteur valide (la borne est `>= 0`, pas `> 0`) : un nœud
    # qui n'a jamais rien écarté, à côté de la liste privée, ne rend pas la répartition inconnue.
    s = "prolongation/noeud_a_zero_reste_lisible"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, "exemple/zero": 0}), env_sup=IMMEDIAT)
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 180, "exemple/zero": 0}), env_sup=IMMEDIAT)
    hb = battement(s, r, evs, declares)
    if hb:
        attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        msg = hb.get("message") or ""
        if f"{PRIVEE} : 100" not in msg or PHRASE_MANDATAIRE not in msg or "répartition inconnue" in msg:
            faute(s, f"compteur à zéro pris pour illisible : {msg!r}")

    # P12 — les dix nœuds nommés sont ceux qui écartent LE PLUS (pas les premiers par le nom), un nom long est
    # coupé à 80 caractères. Ici l'ordre des noms et celui des comptes sont INVERSES.
    s = "prolongation/repartition_ordre_et_troncature"
    long_nom = "exemple/" + "x" * 92 + "YZ"
    treize = {f"exemple/n{i:02d}": i + 1 for i in range(12)}
    treize[long_nom] = 50
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80}), env_sup=IMMEDIAT)
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl(dict(treize, **{PRIVEE: 80})), env_sup=IMMEDIAT)
    hb = battement(s, r, evs, declares)
    if hb:
        msg = hb.get("message") or ""
        for m in (long_nom[:80] + " : 50", "exemple/n11 : 12", "exemple/n03 : 4", "+3 autre(s)"):
            if m not in msg:
                faute(s, f"{m!r} absent de la répartition : {msg!r}")
        for m in (long_nom[:81], "exemple/n02 :", "exemple/n01 :", "exemple/n00 :"):
            if m in msg:
                faute(s, f"{m!r} présent : nœud hors des dix plus gros, ou nom non coupé à 80 : {msg!r}")

    # P13 — un état de listes blanches mal formé (compteur en texte) est rejeté : la répartition repart des
    # totaux depuis le démarrage de l'agent, et le dit ; elle ne se dit pas « sur la fenêtre ».
    s = "prolongation/etat_listes_blanches_mal_forme"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80}), env_sup=IMMEDIAT)
    bac.poser(d, WL_ETAT, json.dumps({PRIVEE: "80"}))
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 180}), env_sup=IMMEDIAT)
    hb = battement(s, r, evs, declares)
    if hb:
        msg = hb.get("message") or ""
        base(s, msg, "demarrage")
        if f"{PRIVEE} : 180" not in msg:
            faute(s, f"état de listes blanches mal formé pris pour une fenêtre : {msg!r}")
        det = (aveux_acquisition(evs) or [{}])[0].get("fields", {}).get("detail", "")
        if REP_DEMARRAGE_A not in det or REP_FENETRE_A in det:
            faute(s, f"base de la répartition fausse dans l'aveu : {det!r}")

    # P14 — `metrics show whitelists` qui réussit SANS section `whitelists` (version qui ne la porte pas) : le
    # repli `cscli metrics -o json` est lu, la répartition est nommée.
    s = "prolongation/show_sans_section_repli"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80, SSO: 8}), env_sup=IMMEDIAT)
    tout = json.dumps(dict(json.loads(M_LB_TOUT), **json.loads(wl({PRIVEE: 170, SSO: 18}))))
    r, evs = bac.passage(d, M_LB_TOUT, wl="{}", metrics_tout=tout, env_sup=IMMEDIAT)
    hb = battement(s, r, evs, declares)
    if hb:
        msg = hb.get("message") or ""
        if f"{PRIVEE} : 90" not in msg or f"{SSO} : 10" not in msg or "répartition inconnue" in msg:
            faute(s, f"repli non lu quand `show whitelists` n'a pas de section : {msg!r}")

    # P15 — ÉTAT NON INSCRIPTIBLE (même technique que `etat_non_inscriptible` : l'état sous un FICHIER). Tout part
    # en liste blanche, l'horodatage ne peut pas se poser : la durée ne court jamais. Sous le seuil, le refus ne
    # partirait JAMAIS ; le capteur refuse donc sans attendre (aussi sévère qu'avant le seuil), le dit, et avoue
    # l'écriture ratée (`etat/horodatage`). Réglage par défaut (24 h) : c'est lui qui tairait le refus.
    def aveu_etat(evs, morceau):
        return [e for e in evs if e.get("category") == "config"
                and morceau in ((e.get("fields") or {}).get("detail") or "")]

    s = "prolongation/horodatage_non_inscriptible"
    d = bac.scenario()
    bouchon = os.path.join(d, "bouchon")
    open(bouchon, "w").close()
    r, evs = bac.passage(d, M_WL1, wl=wl({PRIVEE: 100}), etat=os.path.join(bouchon, "etat"))
    hb = battement(s, r, evs, declares)
    if hb:
        attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        if "horodatage non inscriptible" not in (hb.get("message") or ""):
            faute(s, f"durée qui ne peut pas courir non dite : {hb.get('message')!r}")
        det = (aveux_acquisition(evs) or [{}])[0].get("fields", {}).get("detail", "")
        if "horodatage non inscriptible" not in det:
            faute(s, f"durée qui ne peut pas courir non dite dans l'aveu : {det!r}")
        if len(aveu_etat(evs, "etat/horodatage")) != 1:
            faute(s, "horodatage non posé sans aveu `etat/horodatage`")

    # P16 — échecs d'écriture CIBLÉS par un faux `mktemp` placé devant le vrai dans le PATH du capteur : il échoue
    # pour UN gabarit d'état, délègue le reste. (a) sur un passage qui LIT, l'horodatage ou l'état des listes
    # blanches non posés sont avoués chacun sous son nom, l'état d'acquisition, lui, avance ; (b) sur un passage
    # tout en liste blanche dont l'état d'acquisition est lisible mais l'horodatage absent et non inscriptible :
    # refus sans attendre le seuil, comme en P15.
    faux = os.path.join(bac.racine, "faux-mktemp")
    if not os.path.isdir(faux):
        os.mkdir(faux)
        with open(os.path.join(faux, "mktemp"), "w") as f:
            f.write(f"#!{os.path.realpath(shutil.which('sh'))}\n"
                    f'case "$*" in *"$FAUX_MKTEMP_ECHEC"*) exit 1 ;; esac\n'
                    f'exec {os.path.join(bac.bin, "mktemp")} "$@"\n')
        os.chmod(os.path.join(faux, "mktemp"), stat.S_IRWXU)

    def env_echec(gabarit):
        return {"PATH": faux + ":" + bac.bin, "FAUX_MKTEMP_ECHEC": gabarit}

    for s, gabarit, morceau, autre, nom_etat in (
            ("prolongation/lit/horodatage_non_pose", ".crowdsec-scenarios.", "etat/horodatage",
             "etat/listes-blanches", TS_ETAT),
            ("prolongation/lit/listes_blanches_non_posees", ".crowdsec-whitelists.", "etat/listes-blanches",
             "etat/horodatage", WL_ETAT)):
        d = bac.scenario()
        r, evs = bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80}), env_sup=env_echec(gabarit))
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_sans_refus(s, hb, evs, "premier_passage")
        if len(aveu_etat(evs, morceau)) != 1 or aveu_etat(evs, autre):
            faute(s, f"écriture ratée de {morceau} non avouée, ou {autre} avoué à tort : "
                     f"{[(e.get('fields') or {}).get('detail') for e in evs if e.get('category') == 'config']}")
        if bac.etat(d) is None or bac.etat(d, nom_etat) is not None:
            faute(s, f"état d'acquisition non posé, ou {nom_etat} posé malgré l'échec")
    s = "prolongation/tout/horodatage_absent_non_inscriptible"
    d = bac.scenario()
    bac.passage(d, M_LB_AVANT, wl=wl({PRIVEE: 80}))
    os.remove(os.path.join(d, "etat", TS_ETAT))
    r, evs = bac.passage(d, M_LB_TOUT, wl=wl({PRIVEE: 180}), env_sup=env_echec(".crowdsec-scenarios."))
    hb = battement(s, r, evs, declares)
    if hb:
        attendre_refus(s, hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        if "horodatage non inscriptible" not in (hb.get("message") or ""):
            faute(s, f"durée qui ne peut pas courir non dite : {hb.get('message')!r}")
        if len(aveu_etat(evs, "etat/horodatage")) != 1:
            faute(s, "horodatage non posé sans aveu `etat/horodatage`")


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

        # 3 septies) P10.32-g — AU PREMIER PASSAGE, cent cinquante sources dont SEULE la 150e a lu : les 149 à zéro
        # sont nommées, BORNÉES à 100, sans celle qui lit (la borne du premier passage, sur sa propre branche).
        s = "premier_passage/cent_cinquante_a_zero"
        d = bac.scenario()
        r, evs = bac.passage(d, acq({source_p(i): ({"reads": 10, "parsed": 7, "unparsed": 3} if i == 149 else {"reads": 0})
                                     for i in range(150)}))
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_sans_refus(s, hb, evs, "premier_passage")
            fz = hb["fields"].get("acq_frozen_sources") or []
            if len(fz) != 100 or source_p(149) in fz or len(set(fz)) != 100:
                faute(s, f"acq_frozen_sources : {len(fz)} entrées (borne attendue 100, distinctes, sans la source qui lit)")

        # 3 sexies) une source lit sans rien analyser, une autre analyse : `lit`, et la première
        # n'est PAS nommée figée — elle lit ; son parseur cassé se voit dans son détail.
        # 3 sexies a) P10.32-g — AU PREMIER PASSAGE, une source qui n'a lu AUCUNE ligne depuis le démarrage de
        # l'agent, parmi d'autres qui lisent, est nommée (elle était tue jusqu'au passage suivant), sans refus.
        s = "premier_passage/source_a_zero"
        d = bac.scenario()
        r, evs = bac.passage(d, M1_NEUVE_VIDE)
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_sans_refus(s, hb, evs, "premier_passage")
            egal(s, hb["fields"], "acq_frozen_sources", [S_NEW])

        s = "premier_passage/source_a_une_ligne"
        d = bac.scenario()
        r, evs = bac.passage(d, M1_NEUVE_VIDE_ET_UNE_LIGNE)
        hb = battement(s, r, evs, declares)
        if hb:
            attendre_sans_refus(s, hb, evs, "premier_passage")
            egal(s, hb["fields"], "acq_frozen_sources", [S_NEW])

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
        r, evs = bac.passage(d, M_WL1, env_sup=IMMEDIAT)
        hb = battement(s + "/1", r, evs, declares)
        if hb:
            attendre_refus(s + "/1", hb, evs, "tout_en_liste_blanche", "forme_inconnue")
        r, evs = bac.passage(d, M_WL2, env_sup=IMMEDIAT)
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

        prolongation(bac, declares)

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
