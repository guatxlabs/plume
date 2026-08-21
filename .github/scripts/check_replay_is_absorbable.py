#!/usr/bin/env python3
"""Un rejeu doit être ABSORBÉ, pas seulement visible — garde de CI (`S34`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`S30` a inversé l'ordre des deux gestes d'un capteur incrémental : il PUBLIE d'abord, il ACQUITTE
ensuite. Une coupure entre les deux ne perd donc plus rien — elle produit un REJEU. C'est un progrès,
et il est incomplet : le central n'absorbe ce rejeu que si l'événement PORTE de quoi être reconnu.
Sans clé, l'inversion échange une perte silencieuse contre des DOUBLONS dans les tableaux et les
alertes. Cette garde exige la clé, et refuse qu'un capteur suivant réintroduise le trou.

LE MÉCANISME, DÉRIVÉ PLUTÔT QUE RÉCITÉ
--------------------------------------
Côté central, un événement est reconnu « déjà vu » par UNE chose et une seule : la colonne
`event.dedup`, qui porte un index UNIQUE au niveau de la base (`db/schema.sql`) et dont toute
écriture est un `INSERT OR IGNORE` (`daemon/src/ingest/store.rs`). Le daemon CLOISONNE cette clé par
l'hôte de la ligne au point d'écriture (`dedup_scoped_by_host`), de sorte que deux machines qui
fabriquent la même clé ne se suppriment pas l'une l'autre. Et une clé ABSENTE vaut NULL : SQLite
tient deux NULL pour DISTINCTS, donc **sans clé il n'y a pas de dédoublonnage du tout**, jamais un
dédoublonnage partiel. La partition se dérive donc de cette propriété — « l'événement porte-t-il une
valeur, et cette valeur est-elle la même quand on le republie ? » — et non d'une liste de capteurs.

CE QUE LE DÉCOMPTE PRÉCÉDENT AVAIT MANQUÉ, ET POURQUOI
-----------------------------------------------------
Le décompte annoncé (six absorbés, quatre par seau, sept sans clé) portait sur DIX-SEPT capteurs,
parce qu'il avait hérité de la liste de `S30` — celle des capteurs dont l'ORDRE était fautif. Or la
population qui REJOUE n'est pas celle-là : c'est celle des capteurs qui publient PUIS acquittent,
soit les VINGT-DEUX qui appellent `spool_write_then_ack` / `spool_publish_then_ack`. Quatre capteurs
avaient déjà le bon ordre et rejouent tout autant (`web`, `mail`, `dataaccess`, `resources`). C'est
la même faute qu'auparavant, d'un cran plus haut : une liste reprise au lieu d'une propriété
redérivée. La partition mesurée sur l'arbre, elle, se lit dans le compte-rendu de cette garde.

LA RÈGLE, ÉCRITE COMME UNE CONTRAPOSÉE
--------------------------------------
Tout site d'un capteur REJOUEUR qui construit un objet événement doit porter une clé. La découverte
est faite sur le MOTIF (un objet qui porte `severity` et `source`), pas sur une liste de fichiers :
un capteur écrit demain est couvert par construction. Les battements de santé n'en portent pas et
n'ont pas à en porter — ils passent par `heartbeat` (`collectors/lib.sh`) et ne construisent aucun
objet littéral, donc le motif ne les voit pas ; leur absence de clé est délibérée et documentée là
où elle est décidée (un battement à clé constante figerait `MAX(ts)` et ferait passer un capteur
mort pour un capteur vivant).

DEUX JAMBES, PARCE QU'UNE GARDE STATIQUE NE PROUVE QUE LA FORME
--------------------------------------------------------------
1. STATIQUE : aucun site d'émission sans clé, et pas de dérive du nombre de clés bâties sur un SEAU
   DE L'INSTANT DE COLLECTE (le régime intermédiaire : il absorbe tant que le passage suivant tombe
   dans le même seau, et cesse d'absorber dès qu'une coupure enjambe la frontière).
2. EXÉCUTÉE : les capteurs sont VRAIMENT lancés sur un gabarit, avec une COUPURE SIMULÉE juste après
   la publication (la bibliothèque est chargée par un relais qui fait mourir le processus dans
   l'acquittement), puis relancés. Trois témoins, dont deux vont en SENS INVERSE :
     (a) ABSORPTION — la tranche republiée doit rendre EXACTEMENT les mêmes clés ;
     (b) DISCRIMINATION — des enregistrements réellement différents doivent rendre des clés
         différentes. Sans ce témoin, une clé CONSTANTE passerait (a) brillamment tout en effaçant
         toutes les données. C'est le risque symétrique, et le plus grave : afficher deux fois un
         événement se corrige, perdre un événement réel ne se voit pas ;
     (c) PASSAGES DISTINCTS — un enregistrement neuf, lu au passage suivant, ne doit jamais porter
         une clé déjà employée.

CE QUE LA JAMBE EXÉCUTÉE PROUVE, ET CE QU'ELLE NE PROUVE PAS
------------------------------------------------------------
Elle prouve que la clé émise ne dépend NI de l'instant de publication, NI du numéro de passage, NI du
processus — c'est le piège central, et il est mesuré, pas supposé. Elle NE PROUVE PAS que le central
range bien ces lignes : c'est le rôle des tests du daemon, qui font passer les mêmes formes de clé
par le VRAI chemin d'ingestion. Les deux moitiés se tiennent, aucune ne suffit seule.
Deux outils externes sont REMPLACÉS par des relais (le point de reprise d'`ausearch`, l'inventaire
`crictl`) : ce qui est alors éprouvé est la façon dont le capteur DÉRIVE sa clé, pas le comportement
de l'outil. Le format du point de reprise employé par le relais est celui qu'écrit `ausearch`
(`dev=` / `inode=` / `output=<nœud> <sec>.<msec>:<serial> <fanions>`), relevé sur l'outil réel.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

LIB = "collectors/lib.sh"

# --- PLANCHERS ET PLAFOND, pas des listes ---------------------------------------------------------
# Les planchers ferment le seul vrai mode de panne d'une garde par balayage : une découverte cassée
# qui ne lit RIEN et rapporte un vert joyeux. MESURÉ le 2026-08-21 sur l'arbre : 22 capteurs
# rejoueurs, 26 sites d'émission.
MIN_REJOUEURS = 18
MIN_SITES = 22
# PLAFOND du régime intermédiaire. Ces clés-là portent un SEAU de l'instant de collecte au lieu d'une
# identité : c'est une AGRÉGATION VOULUE (un même scanneur ne doit pas remplir un tableau de bord),
# et elle n'est pas un défaut. Mais elle a un coût qu'il faut garder sous les yeux : une coupure qui
# enjambe la frontière du seau n'est PAS absorbée. Le plafond empêche que ce régime s'étende par
# copier-coller. MESURÉ le 2026-08-21 : 4 sites, un par capteur (`ufw` seau horaire, `portscan`
# 5 min, `origin-drop` 1 min, `kube-audit` empreinte + 10 min).
MAX_SITES_A_SEAU = 4
# Nombre minimal de capteurs réellement LANCÉS par la jambe exécutée (les autres demandent un service
# externe qu'un relais ne saurait pas imiter honnêtement).
MIN_CAPTEURS_EXERCES = 6

ACK = re.compile(r"spool_(?:write|publish)_then_ack")
SEVERITE = re.compile(r'(?:\\?")?severity\\?"?\s*:')
SOURCE = re.compile(r'(?:\\?")?source\\?"?\s*:')
CLE = re.compile(r"dedup")
# Un seau de l'INSTANT DE COLLECTE : `ts` divisé, dans la même expression que la clé.
SEAU = re.compile(r"\bts\s*/\s*\d+")
CATEGORIE_CONFIG = re.compile(r'category\\?"?\s*:\s*\\?"config')

AVANT, APRES = 8, 13


def echec(msg):
    print(f"::error::{msg}")
    print(f"check_replay_is_absorbable : {msg}", file=sys.stderr)
    sys.exit(1)


def strip_comment(ligne):
    """Retire un commentaire `#` hors guillemets. Un `#` dans "..." n'en ouvre pas un."""
    out, quote, i = [], None, 0
    while i < len(ligne):
        c = ligne[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append(c)
                i += 1
                if i < len(ligne):
                    out.append(ligne[i])
                i += 1
                continue
            if c == quote:
                quote = None
            out.append(c)
            i += 1
            continue
        if c in "\"'":
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "#" and (not out or out[-1] in " \t"):
            break
        out.append(c)
        i += 1
    return "".join(out)


def sites_demission(lignes):
    """Rend [(no_ligne, fenêtre)] pour chaque objet événement construit dans du CODE."""
    trouves = []
    for i, l in enumerate(lignes):
        if not SEVERITE.search(l):
            continue
        fen = "\n".join(lignes[max(0, i - AVANT) : i + APRES])
        if not SOURCE.search(fen):
            continue
        trouves.append((i + 1, fen))
    return trouves


def valider_l_instrument():
    """DEUX TÉMOINS avant de croire le balayage — et le NÉGATIF a déjà mordu.

    Un premier jet cherchait `dedup` dans le texte BRUT : un capteur dont un COMMENTAIRE voisin
    expliquait pourquoi il n'a pas de clé passait alors pour un capteur à clé. Le mot suffisait. La
    garde aurait rendu vert en étant aveugle, exactement sur le capteur le plus exposé au rejeu.
    """
    positif = ['events="{\\"ts\\":1,\\"source\\":\\"x\\",\\"severity\\":2,\\"dedup\\":\\"k\\"}"']
    if not sites_demission([strip_comment(l) for l in positif]):
        echec("INSTRUMENT : un site d'émission NORMAL n'est plus reconnu — le balayage ne voit rien")
    negatif = [
        "# ce capteur n'a pas de dedup, et voici pourquoi",
        'events="{\\"ts\\":1,\\"source\\":\\"x\\",\\"severity\\":2}"',
    ]
    lignes = [strip_comment(l) for l in negatif]
    sites = sites_demission(lignes)
    if not sites:
        echec("INSTRUMENT : le témoin négatif ne produit aucun site — il ne mesure rien")
    if CLE.search(sites[0][1]):
        echec(
            "INSTRUMENT : un COMMENTAIRE contenant le mot `dedup` satisfait la règle — la garde "
            "serait contentée par une phrase au lieu d'une clé"
        )


def jambe_statique():
    rejoueurs, sites_total, fautifs, a_seau = [], 0, [], []
    for f in sorted(glob.glob("collectors/*.sh")):
        if os.path.basename(f) == "lib.sh":
            continue
        brut = open(f, encoding="utf-8").read()
        if not ACK.search(brut):
            continue
        rejoueurs.append(f)
        lignes = [strip_comment(l) for l in brut.splitlines()]
        for no, fen in sites_demission(lignes):
            sites_total += 1
            if not CLE.search(fen):
                fautifs.append((f, no))
            elif SEAU.search(fen) and not CATEGORIE_CONFIG.search(fen):
                a_seau.append((f, no))

    if fautifs:
        for f, no in fautifs:
            print(
                f"::error file={f},line={no}::{f} : objet événement sans clé d'identité — "
                "le rejeu produit par l'ordre publier-puis-acquitter n'y sera pas absorbé"
            )
        echec(
            f"{len(fautifs)} site(s) d'émission sans clé, dans : "
            + ", ".join(sorted({f for f, _ in fautifs}))
            + " — un capteur qui publie puis acquitte REJOUE après coupure ; sans `dedup`, la "
              "colonne vaut NULL, SQLite tient deux NULL pour distincts, et chaque rejeu ajoute une "
              "ligne. Prenez la clé DANS ce que le capteur observe (horodatage du record, "
              "identifiant du noyau, empreinte du contenu) — jamais dans l'instant de publication, "
              "le numéro de passage ou le processus. Si le record n'offre RIEN de stable ET de "
              "discriminant, dites-le : une clé fausse efface des événements réels."
        )
    if len(rejoueurs) < MIN_REJOUEURS:
        echec(f"plancher : {len(rejoueurs)} capteur(s) rejoueur(s) (< {MIN_REJOUEURS}) — découverte cassée")
    if sites_total < MIN_SITES:
        echec(f"plancher : {sites_total} site(s) d'émission (< {MIN_SITES}) — découverte cassée")
    if len(a_seau) > MAX_SITES_A_SEAU:
        for f, no in a_seau:
            print(f"::error file={f},line={no}::{f} : clé bâtie sur un seau de l'instant de collecte")
        echec(
            f"{len(a_seau)} clé(s) à seau de temps (> {MAX_SITES_A_SEAU}) — ce régime absorbe le "
            "rejeu tant que le passage suivant tombe dans le même seau, et cesse d'absorber dès "
            "qu'une coupure enjambe la frontière. Il est acceptable là où le seau EST l'agrégation "
            "voulue ; il ne doit pas s'étendre par recopie."
        )
    return rejoueurs, sites_total, a_seau


# =================================================================================================
# JAMBE EXÉCUTÉE
# =================================================================================================
RELAIS_COUPURE = """. "{lib}"
_plume_ack_commit() {{ kill -9 $$; }}
"""


def cles_du_spool(spool, quoi):
    """Clés des événements de DONNÉES publiés — hors config et hors battement de santé.

    Une enveloppe illisible est une ERREUR BRUYANTE, pas une enveloppe vide : l'ignorer ferait
    ressembler du JSON cassé — le mode de panne exact qu'une clé mal échappée produit — à un passage
    sans événement, et la garde rendrait un diagnostic faux sur la bonne panne.
    """
    cles, sans_cle = [], 0
    for nom in sorted(os.listdir(spool)):
        if not nom.endswith(".json") or nom.startswith("."):
            continue
        brut = open(os.path.join(spool, nom), encoding="utf-8").read()
        try:
            doc = json.loads(brut)
        except ValueError as e:
            echec(
                f"{quoi} : l'enveloppe `{nom}` n'est pas du JSON valide ({e}) — une clé mal échappée "
                f"casse le lot ENTIER, pas seulement sa propre ligne. Début : {brut[:200]!r}"
            )
        if doc.get("kind") != "events":
            continue
        for ev in doc.get("events", []):
            if ev.get("category") in ("config", "health"):
                continue
            if "dedup" in ev:
                cles.append(ev["dedup"])
            else:
                sans_cle += 1
    return cles, sans_cle


class Bac:
    """Un bac à sable : spool, état, relais d'outils externes, gabarit."""

    def __init__(self, base, nom):
        self.racine = os.path.join(base, nom)
        self.spool = os.path.join(self.racine, "spool")
        self.etat = os.path.join(self.racine, "state")
        self.binz = os.path.join(self.racine, "bin")
        self.gab = os.path.join(self.racine, "gabarit")
        for d in (self.spool, self.etat, self.binz, self.gab):
            os.makedirs(d)

    def relais_horloge(self):
        """DÉCALE L'HORLOGE ENTRE DEUX PASSES, ET C'EST INDISPENSABLE.

        Un premier jet lançait les passes à la suite. Elles tombaient dans la MÊME SECONDE, et une
        clé à laquelle on ajoutait l'instant de publication passait le témoin d'absorption : le
        témoin ne mesurait pas ce qu'il annonçait. `date +%s` est donc relayé, et chaque passe voit
        une seconde différente — le piège central de cette clé (une clé qui contient l'instant de
        publication) devient alors impossible à ne pas voir.
        """
        reel = shutil.which("date")
        if reel is None:
            echec("aucun `date` — le relais d'horloge ne peut pas être validé")
        self.relais(
            "date",
            "#!/bin/sh\n"
            f'if [ "$1" = "+%s" ] && [ $# -eq 1 ]; then\n'
            f'  printf "%s\\n" "$(( $({reel} +%s) + ${{PLUME_RELAIS_DECALAGE:-0}} ))"\n'
            "  exit 0\n"
            "fi\n"
            f'exec {reel} "$@"\n',
        )
        # TÉMOIN POSITIF ET TÉMOIN NÉGATIF : le relais doit décaler quand on le lui demande, et
        # rendre l'heure réelle quand on ne lui demande rien. Un relais qui ne décalerait pas ferait
        # passer le témoin d'absorption pour vert sans qu'il ait rien mesuré.
        vu = {}
        for dec in ("0", "4321"):
            r = subprocess.run(
                ["sh", "-c", "date +%s"],
                env=self.env({"PLUME_RELAIS_DECALAGE": dec}),
                capture_output=True,
                text=True,
            )
            if r.returncode != 0 or not r.stdout.strip().isdigit():
                echec(f"INSTRUMENT : le relais d'horloge ne rend pas de seconde ({r.stderr.strip()})")
            vu[dec] = int(r.stdout.strip())
        if vu["4321"] - vu["0"] < 4000:
            echec(
                "INSTRUMENT : le relais d'horloge ne décale pas — les passes tomberaient dans la "
                "même seconde et une clé bâtie sur l'instant de publication passerait pour stable"
            )

    def relais(self, nom, corps):
        chemin = os.path.join(self.binz, nom)
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(corps)
        os.chmod(chemin, 0o755)

    def env(self, sup=None):
        e = dict(
            os.environ,
            PATH=self.binz + os.pathsep + os.environ.get("PATH", ""),
            PLUME_SPOOL=self.spool,
            PLUME_STATE=self.etat,
        )
        e.update(sup or {})
        return e

    def passage(self, capteur, coupure, sup=None, decalage=0):
        """Lance le capteur. `coupure` = le processus meurt DANS l'acquittement, après publication."""
        for n in os.listdir(self.spool):
            os.remove(os.path.join(self.spool, n))
        lib = os.path.abspath(LIB)
        if coupure:
            shim = os.path.join(self.racine, "relais-lib.sh")
            with open(shim, "w", encoding="utf-8") as f:
                f.write(RELAIS_COUPURE.format(lib=lib))
        else:
            shim = lib
        env = self.env(sup)
        env["PLUME_LIB"] = shim
        env["PLUME_RELAIS_DECALAGE"] = str(decalage)
        subprocess.run(["sh", os.path.abspath(capteur)], env=env, capture_output=True, text=True)
        return cles_du_spool(self.spool, os.path.basename(capteur))


def temoins(nom, bac, capteur, gabarit_initial, gabarit_augmente, attendus, sup=None):
    """Les trois témoins, pour un capteur. Rend le nombre de clés vues au premier passage."""
    gabarit_initial()
    bac.relais_horloge()
    cles_coupure, sans_cle = bac.passage(capteur, coupure=True, sup=sup, decalage=0)
    if sans_cle:
        echec(
            f"{nom} : {sans_cle} événement(s) de DONNÉES publié(s) SANS clé. Le motif statique les a "
            "laissés passer, mais à l'exécution la clé n'est pas attachée (branche non prise, "
            "variable vide) — le rejeu de ces lignes-là ne sera pas absorbé."
        )
    if not cles_coupure:
        echec(
            f"{nom} : le passage interrompu n'a publié AUCUNE clé — ce témoin ne mesurerait rien "
            "(gabarit non lu, ou capteur sorti avant de publier)"
        )
    if len(cles_coupure) != attendus:
        echec(
            f"{nom} : {len(cles_coupure)} clé(s) au lieu des {attendus} enregistrements du gabarit "
            "— le témoin ne porte pas sur ce qu'il croit"
        )
    # (b) DISCRIMINATION — le témoin qui démasque une clé constante.
    if len(set(cles_coupure)) != len(cles_coupure):
        echec(
            f"{nom} : deux enregistrements DIFFÉRENTS partagent une clé ({sorted(cles_coupure)}) — "
            "le central en effacerait un. Perdre un événement réel est pire qu'en afficher deux."
        )
    # (a) ABSORPTION — la tranche republiée doit rendre EXACTEMENT les mêmes clés.
    cles_rejeu, _ = bac.passage(capteur, coupure=False, sup=sup, decalage=4001)
    if sorted(cles_rejeu) != sorted(cles_coupure):
        echec(
            f"{nom} : le rejeu après coupure ne reproduit pas les mêmes clés.\n"
            f"  publiées avant la coupure : {sorted(cles_coupure)}\n"
            f"  republiées au passage suivant : {sorted(cles_rejeu)}\n"
            "La clé dépend donc de quelque chose du PASSAGE (instant de publication, numéro de "
            "passage, processus) et non de l'événement : le central ne l'absorbera pas."
        )
    # (c) PASSAGES DISTINCTS — un enregistrement neuf ne réemploie jamais une clé déjà vue.
    gabarit_augmente()
    cles_neuves, _ = bac.passage(capteur, coupure=False, sup=sup, decalage=8002)
    if not cles_neuves:
        echec(f"{nom} : le gabarit augmenté n'a produit aucune clé — ce troisième témoin est aveugle")
    collision = sorted(set(cles_neuves) & set(cles_coupure))
    if collision:
        echec(
            f"{nom} : un enregistrement NEUF réemploie une clé du passage précédent ({collision}) — "
            "le central effacerait un événement réel"
        )
    return len(cles_coupure)


def ecrire(chemin, texte):
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(texte)


def ajouter(chemin, texte):
    with open(chemin, "a", encoding="utf-8") as f:
        f.write(texte)


FALCO = (
    '{{"time":"2026-08-21T10:0{n}:00.12345678{n}Z","rule":"Regle {n}","priority":"Warning",'
    '"output":"detection numero {n}","output_fields":{{"proc.name":"sh"}}}}\n'
)
SURICATA = (
    '{{"timestamp":"2026-08-21T10:0{n}:00.12345{n}+0000","flow_id":100{n},"event_type":"alert",'
    '"src_ip":"198.51.100.{n}","dest_ip":"203.0.113.1","alert":{{"signature":"IDS regle {n}",'
    '"severity":1,"signature_id":200{n}}}}}\n'
)
AUDITD = (
    'type=SYSCALL msg=audit(1755766000.10{n}:471{n}): arch=c000003e syscall=59 success=yes exit=0 '
    "items=0 ppid=100 pid=10{n} auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=1 "
    'comm="outil{n}" exe="/usr/bin/outil{n}" key="exec_tracking"\n'
)
POD = "2026-08-21T10:0{n}:00.12345678{n}Z stdout F acces denied pour la requete {n}\n"


def capteurs_exercables(base):
    """Rend [(nom, fabrique_du_bac)] — chaque fabrique monte le gabarit et rend les 5 arguments."""
    liste = []

    # --- falco : un journal JSON, lu par offset -------------------------------------------------
    def falco():
        bac = Bac(base, "falco")
        log = os.path.join(bac.gab, "falco.txt")
        return (
            "falco",
            bac,
            "collectors/falco.sh",
            lambda: ecrire(log, "".join(FALCO.format(n=i) for i in (1, 2, 3))),
            lambda: ajouter(log, FALCO.format(n=4)),
            3,
            {"PLUME_FALCO_LOG": log},
        )

    # --- suricata : un eve.json, lu par offset ---------------------------------------------------
    def suricata():
        bac = Bac(base, "suricata")
        eve = os.path.join(bac.gab, "eve.json")
        return (
            "suricata",
            bac,
            "collectors/suricata.sh",
            lambda: ecrire(eve, "".join(SURICATA.format(n=i) for i in (1, 2, 3))),
            lambda: ajouter(eve, SURICATA.format(n=4)),
            3,
            {"PLUME_SURICATA_EVE": eve},
        )

    # --- auditd : le journal du noyau, lu par offset ---------------------------------------------
    def auditd():
        bac = Bac(base, "auditd")
        log = os.path.join(bac.gab, "audit.log")
        return (
            "auditd",
            bac,
            "collectors/auditd.sh",
            lambda: ecrire(log, "".join(AUDITD.format(n=i) for i in (1, 2, 3))),
            lambda: ajouter(log, AUDITD.format(n=4)),
            3,
            {"PLUME_AUDIT_LOG": log},
        )

    # --- pod-logs : l'arborescence des journaux de pods, offset PAR FICHIER ----------------------
    def podlogs():
        bac = Bac(base, "pod-logs")
        rep = os.path.join(bac.gab, "pods")
        fic = os.path.join(rep, "ns-demo_appli-demo_0000-uid", "conteneur", "0.log")
        return (
            "pod-logs",
            bac,
            "collectors/pod-logs.sh",
            lambda: ecrire(fic, "".join(POD.format(n=i) for i in (1, 2, 3))),
            lambda: ajouter(fic, POD.format(n=4)),
            3,
            {"PLUME_POD_LOG_DIR": rep, "PLUME_POD_LOG_SKIP": ""},
        )

    # --- containerd : inventaire CRI, relais de `crictl` -----------------------------------------
    def containerd():
        bac = Bac(base, "containerd")
        table = os.path.join(bac.gab, "images.txt")

        def pose(n):
            lignes = ["IMAGE TAG IMAGEID SIZE"]
            lignes += [f"exemple/image{i} v1 sha256:{i:064d} 10MB" for i in range(1, n + 1)]
            ecrire(table, "\n".join(lignes) + "\n")

        bac.relais(
            "crictl",
            '#!/bin/sh\n[ "$1" = images ] || exit 1\ncat "$PLUME_RELAIS_IMAGES"\n',
        )
        sup = {"PLUME_RELAIS_IMAGES": table}

        def reference():
            # 1er passage : le registre « deja signale » se pose sur l'inventaire courant, et RIEN
            # n'est signale (pas d'inondation au demarrage). Les images suivantes sont le constat.
            pose(1)
            env = bac.env(dict(sup, PLUME_LIB=os.path.abspath(LIB)))
            subprocess.run(
                ["sh", os.path.abspath("collectors/containerd.sh")], env=env, capture_output=True, text=True
            )
            pose(4)

        return (
            "containerd",
            bac,
            "collectors/containerd.sh",
            reference,
            lambda: pose(5),
            3,
            sup,
        )

    # --- integrity : référence + différentiel, relais de `find` ----------------------------------
    def integrity():
        bac = Bac(base, "integrity")
        surveilles = os.path.join(bac.gab, "surveilles")
        os.makedirs(surveilles)
        bac.relais("find", "#!/bin/sh\nexit 0\n")   # aucun binaire SUID : le différentiel vient des fichiers suivis
        bac.relais("ss", "#!/bin/sh\nexit 1\n")     # aucun port en écoute : ils n'ont pas de clé, par décision

        fichiers = [os.path.join(surveilles, f"fichier{i}") for i in (1, 2, 3, 4)]

        def reference():
            for f in fichiers[:1]:
                ecrire(f, "reference\n")
            # 1er passage : la référence se pose, rien n'est signalé. Les 3 suivants sont le constat.
            subprocess.run(
                ["sh", os.path.abspath("collectors/integrity.sh")],
                env=bac.env({"PLUME_FIM_FILES": " ".join(fichiers), "PLUME_LIB": os.path.abspath(LIB)}),
                capture_output=True,
                text=True,
            )
            for i, f in enumerate(fichiers[1:4], start=2):
                ecrire(f, f"contenu numero {i}\n")

        return (
            "integrity",
            bac,
            "collectors/integrity.sh",
            reference,
            lambda: ecrire(fichiers[0], "contenu modifie\n"),
            3,
            {"PLUME_FIM_FILES": " ".join(fichiers)},
        )

    # --- audit : point de reprise tenu par un outil externe, relais d'`ausearch` -----------------
    def audit():
        bac = Bac(base, "audit")
        table = os.path.join(bac.gab, "records.tsv")
        bac.relais(
            "ausearch",
            "#!/bin/sh\n"
            "# Relais d'`ausearch --checkpoint` : rend les enregistrements POSTÉRIEURS au point de\n"
            "# reprise et réécrit celui-ci. Le FORMAT est celui de l'outil réel (relevé le\n"
            "# 2026-08-21) : `dev=` / `inode=` / `output=<noeud> <sec>.<msec>:<serial> <fanions>`.\n"
            "ck=\"\"\n"
            'while [ $# -gt 0 ]; do if [ "$1" = --checkpoint ]; then ck="$2"; shift; fi; shift; done\n'
            "depuis=$(sed -n 's/^output=[^ ]* \\([^ ]*\\) .*/\\1/p' \"$ck\" 2>/dev/null | head -1)\n"
            '[ -n "$depuis" ] || depuis=0\n'
            "dernier=\"$depuis\"\n"
            "while IFS='\t' read -r serial texte; do\n"
            '  [ -n "$serial" ] || continue\n'
            '  [ "$(printf %s "$serial" | tr -d ".:")" -gt "$(printf %s "$depuis" | tr -d ".:")" ] || continue\n'
            '  printf "%s\\n" "$texte"\n'
            '  dernier="$serial"\n'
            'done < "$PLUME_RELAIS_RECORDS"\n'
            '[ -n "$ck" ] && printf "dev=0x1\\ninode=1\\noutput=- %s 0x0\\n" "$dernier" > "$ck"\n'
            "exit 0\n",
        )

        def pose(n):
            ecrire(
                table,
                "".join(
                    f"1755766000.10{i}:471{i}\tAt 10:46:4{i} 08/21/2026 le compte a execute /usr/bin/outil{i}\n"
                    for i in range(1, n + 1)
                ),
            )

        return (
            "audit",
            bac,
            "collectors/audit.sh",
            lambda: pose(3),
            lambda: pose(4),
            3,
            {"PLUME_RELAIS_RECORDS": table},
        )

    for fabrique in (falco, suricata, auditd, podlogs, containerd, integrity, audit):
        liste.append(fabrique())
    return liste


def jambe_executee():
    if shutil.which("sh") is None:
        echec("aucun `sh` — la jambe exécutée ne rendra pas un faux vert")
    exerces, cles_vues = [], 0
    with tempfile.TemporaryDirectory() as base:
        for nom, bac, capteur, avant, apres, attendus, sup in capteurs_exercables(base):
            cles_vues += temoins(nom, bac, capteur, avant, apres, attendus, sup)
            exerces.append(nom)
    if len(exerces) < MIN_CAPTEURS_EXERCES:
        echec(
            f"plancher : {len(exerces)} capteur(s) réellement lancé(s) (< {MIN_CAPTEURS_EXERCES}) — "
            "la jambe exécutée ne prouve plus rien"
        )
    return exerces, cles_vues


def main():
    if not os.path.exists(LIB):
        echec(f"{LIB} introuvable — exécutez cette garde depuis la racine du dépôt")
    valider_l_instrument()
    rejoueurs, sites, a_seau = jambe_statique()
    exerces, cles = jambe_executee()
    capteurs_a_seau = sorted({os.path.basename(f) for f, _ in a_seau})
    print(
        f"check_replay_is_absorbable : {len(rejoueurs)} capteur(s) rejoueur(s), {sites} site(s) "
        f"d'émission, tous porteurs d'une clé ; {len(a_seau)} clé(s) à seau de temps "
        f"({', '.join(capteurs_a_seau)}) — absorbées SEULEMENT dans le même seau. "
        f"{len(exerces)} capteur(s) lancés pour de vrai ({', '.join(exerces)}), {cles} clé(s) "
        "observées : coupure simulée après publication, tranche republiée à l'identique, "
        "enregistrements distincts non confondus, passages distincts sans réemploi. "
        "Prouve la STABILITÉ et la DISCRIMINATION des clés, pas leur rangement côté central "
        "(tests du daemon)."
    )


if __name__ == "__main__":
    main()
