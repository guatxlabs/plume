#!/usr/bin/env python3
"""Un capteur vivant ne se lit ni MUET ni CALME par la faute de sa propre forme — garde de CI (`P10.32-k`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Des capteurs disaient faux sur eux-mêmes, dans les deux sens :
  · `auditd.sh` construisait le JSON de chaque événement dans une boucle shell (`while read`, deux
    `json_escape` par ligne, une chaîne reconstruite à chaque tour) : un passage sur un journal volumineux
    dépassait la cadence de la sonde et le capteur se lisait MUET. Son plafond `PLUME_AUDIT_MAX` coupait par
    `head`, en silence, et les TAMPER — écrits en dernier — partaient les premiers ;
  · `web.sh` n'émettait aucun battement alors que la sonde `web` est continue : un trafic calme se lisait
    « capteur mort » ;
  · `crowdsec.sh` rendait `acq_verdict=lit` quand la liste blanche des adresses privées absorbait toutes
    les lignes analysées (adresse cliente = relais d'un mandataire) : un faux calme ;
  · `minio.sh` et `dataacl.sh` sortaient en silence quand leur cible manquait ;
  · `dataaccess.sh` se disait « actif » quand seules les règles d'audit de /etc étaient chargées.

CE QUE LA GARDE FAIT — ELLE JOUE LES CAPTEURS LIVRÉS, JAMAIS UNE COPIE DE LEUR LOGIQUE
-------------------------------------------------------------------------------------
Chaque capteur est exécuté tel qu'il est dans `collectors/`, dans un bac : `PATH` réduit à un répertoire
d'outils (les vrais, liés, plus des FAUX exécutables — `date` à heure fixe, `auditctl`, `cscli`,
`kubectl` —), spool, état et temporaires dans un répertoire jetable. Le juge lit le spool.
  A. auditd, sous CHAQUE awk présent (gawk, mawk) :
     · DIFFÉRENTIEL — `collectors/auditd-differentiel.corpus`, quatre réglages (défaut, exec_drop,
       exec_drop + recon, real_user_only) : chaque fichier que l'ANCIENNE construction publiait
       (`collectors/auditd-differentiel.attendu.json`, rendu par elle) est rendu à l'octet près ; seul
       l'ordre des TAMPER, qui suit le parcours d'un tableau awk et diffère d'un awk à l'autre, est comparé
       en multiensemble. Un seul fichier de plus est admis : le battement ;
     · STRUCTURE, PAS CHRONOMÈTRE — le même passage sur le corpus et sur vingt copies de lui (identifiants
       noyau distincts) doit exécuter EXACTEMENT autant de commandes shell (marques de trace `sh -x`, comptées dans toute la sortie) et
       lancer EXACTEMENT autant de processus (outils enveloppés qui se comptent). Une boucle shell par
       événement, ou un processus par événement, fait croître l'un des deux comptes ;
     · BATTEMENT `source=auditd category=health` à chaque passage qui lit une tranche neuve, y compris
       quand elle ne donne aucun événement, avec lignes lues, émises, écartées par filtre et au-delà du
       plafond ; AUCUN battement quand le journal n'a pas grossi (journal figé = auditd arrêté : le silence
       est le signal de `de-auditd-silent` et de la sonde, il ne doit pas être couvert) ;
     · PLAFOND AVOUÉ — `PLUME_AUDIT_MAX` bas : les TAMPER passent d'abord, puis les autres par gravité
       décroissante, les premiers de la tranche dans une même gravité, et les gardés sortent dans l'ordre
       d'avant (ordre de la tranche, TAMPER en dernier) ; une tranche SATURÉE d'execve bénins (sev 1) ne
       pousse plus hors du plafond un `svc_exec` (sev 3) ni un exec en échec (sev 2) qui la suivent ; le
       nombre écarté est dans le battement et dans l'aveu `collection-capped` ; un plafond illisible
       retombe sur son défaut et le dit (`unreadable-config`) ;
     · LES DEUX ÉCARTS NOMMÉS par le capteur — un enregistrement sans identifiant `audit(...)` est émis
       (sans clé), un contrôle brut ou un octet UTF-8 invalide dans une valeur laisse l'enveloppe lisible ;
     · ÉCHECS DE L'ANALYSE (premier awk, second awk, comptes illisibles) : avoués `missing-source`, sans
       battement ni enveloppe, et la tranche est rendue entière au passage suivant ; un passage coupé à
       `PLUME_AUDIT_MAX=0` publie encore sa configuration de collecte ;
     · aucun temporaire laissé dans TMPDIR, après aucun passage d'aucun capteur.
  B. web, sous chaque awk : battement à chaque passage qui a vu une requête NEUVE (publiée, filtrée, coupée),
     comptes justes ; AUCUN battement sur un journal figé (deux passages), une lecture vide, un `kubectl logs`
     sans pod (vide, code 0), ni sur une lecture en échec, qui s'avoue. Plafond de 9000 : les lignes coupées
     d'une seconde postérieure au filigrane sont dites reportées et publiées au passage suivant, celles de la
     même seconde dites perdues et avouées (`collection-capped`) ; une ligne FILTRÉE qui suit le plafond ne
     fait pas avancer le filigrane au-delà d'une ligne coupée (publiée au passage suivant, aucune perte dite).
     La borne `PLUME_WEB_MAX` atteinte est dite. `P10.33-e` — elle ne fait plus perdre en silence : en mode file
     (offset d'octets), un flot de sondages filtrés qui noie cinq requêtes réelles sous la borne 3 les laisse
     TOUTES publiées sur les passages suivants, sans aveu ; l'offset tient lieu de filigrane : une seconde
     coupée en deux par la borne (cinq requêtes à la seconde 5, borne 3) est publiée en entier, une requête
     longue au StartUTC antérieur au filigrane aussi, rien n'est dit « déjà vu » ; au premier passage, le début
     du journal non lu est dit, sans « rien n'est sauté » ; borne atteinte pile : dite telle ; une dernière ligne
     en cours d'écriture n'est lue qu'une fois complète ; l'offset s'arrête devant la première ligne coupée par
     le plafond : en mode file, les lignes coupées sont toutes relues et publiées, aucune n'est dite perdue (en
     k3s, la sémantique de `P10.32-k` est gardée) ; rotation par renommage ou `copytruncate` : le reste est lu
     dans `.1`, sans aveu ; `logrotate create` (journal neuf vide pendant la lecture de `.1`) : pas d'aveu ;
     rotation au milieu d'une écriture : la ligne incomplète de `.1` est lue, puis le journal neuf ; journal
     remplacé par un autre plus long que l'offset (empreinte de la première ligne) : lu depuis 0, rotation
     avouée ; même première ligne mais plus court que l'offset, `.1` introuvable ou journal tronqué : rotation
     avouée (`missing-source`) ; deux rotations entre deux passages (le `.1` n'est plus le journal lu), ou un
     `.1` de même première ligne mais plus court que l'offset : perte avouée, rien du `.1` publié. En k3s (faux
     `kubectl` FIDÈLE : `--tail` par pod, pods bout à bout, et 10 lignes par pod sous `-l` sans `--tail`, comme
     le vrai) : les lignes plus anciennes de la fenêtre sont comptées par un second appel à `--tail` explicite
     (10 × la borne), de fenêtre `--since` plus large, borné à l'horodatage runtime le PLUS RÉCENT des lignes
     lues (deux pods : la dernière ligne n'est pas la plus récente ; deux lignes arrivées entre les deux appels,
     dont une à la fraction tronquée par RFC3339Nano, ne comptent pas) et avouées (`collection-capped`, nombre
     exact : 80 sur 100 à la borne 20 ; les requêtes sous le filigrane n'en sont pas) ; un comptage qui atteint
     son propre `--tail` dit « au moins N » ; un comptage en échec, qui voit moins de requêtes que la lecture
     (journal du pod tourné entre les deux appels) ou des horodatages hors `Z` avoue « nombre inconnu » ; sous la
     borne, ni second appel (appels du faux `kubectl` comptés) ni aveu ; des lignes hors journal d'accès dans la
     fenêtre (y compris une qui porte `StartUTC` sans `DownstreamStatus`) ne faussent pas le compte.
  C. crowdsec : `tout_en_liste_blanche` (refus, cause `forme_inconnue`, cause probable nommée, état non
     avancé), au premier passage et sur l'intervalle ; `surtout_liste_blanche` au seuil (sévérité 2, état
     avancé, pas d'aveu) ; seuil réglable par `PLUME_CROWDSEC_WHITELIST_SHARE_MAX`, illisible -> repli dit ;
     une ligne versée à un scénario interdit `tout_en_liste_blanche` ; sous le seuil, `lit` et la part dite ;
     le seuil est ATTEINT à 90 % exactement (89 % : `lit`) ; la forme de comptage disjointe (`reads` =
     `parsed` + `unparsed` + `whitelisted`) est départagée par `reads` : 100 analysées hors liste blanche non
     versées ne sont pas un refus (50 %), 0 analysée hors liste blanche en est un.
  E. minio : API qui échoue -> `unreachable` ; aucun pod en marche -> `subsystem-absent`.
  F. dataaccess : seules les clés /etc chargées -> battement PARTIEL et aveu (clé de dédoublonnage stable,
     texte qui ne promet aucune relecture) ; `plume_data` OU `plume_creds` chargée -> actif, sans aveu ; une
     clé au nom voisin (`plume_data_archive`) ne compte pas. `auditctl` absent ou en échec — toujours, sous
     l'unité livrée qui n'a pas CAP_AUDIT_CONTROL (`P10.33-b`) — : les clés sont PROUVÉES par le journal
     (SYSCALL `key=`, CONFIG_CHANGE `op=add_rule … res=1`, y compris suivi des champs enrichis, y compris
     dans le journal tourné `.1`), une preuve est annulée par un `remove_rule` réussi postérieur (pas par un
     retrait refusé, ni un ajout refusé ne prouve), une clé voisine ne prouve rien ; un DAEMON_START efface les
     preuves qui le précèdent (redémarrage sans rechargement de `plume_data`, accès d'avant le redémarrage,
     sous le préfixe `node=`, DAEMON_START dans le journal courant après une preuve du `.1`), une clé rechargée
     après lui est prouvée ; un journal courant illisible (un répertoire à sa place) n'en laisse aucune, même
     prouvée dans le `.1`, et la lecture s'avoue en échec ; sans clé de données
     prouvée, le battement dit « couverture INCONNUE » en sévérité 1, jamais « actif », et sans aveu
     `unavailable` ; un `auditctl` lisible fait foi contre le journal.
  G. dataacl, sous chaque awk : aucun chemin de `PLUME_ACL_PATHS` existant (absents, glob sans
     correspondance) -> UN aveu `unavailable/missing-source` qui nomme la variable, aucune carte ; un chemin
     présent à côté d'absents ->
     carte inchangée (répertoires + fichier à risque), AUCUN aveu ; un chemin présent mais illisible (mode
     000) -> aveu `missing-source` qui le nomme, lui seul, sans taire la carte des autres ni son entrée de tête.
Partout : sortie 0, enveloppes de spool lisibles comme JSON, aucun fichier caché laissé dans le spool, et
les champs de chaque battement déclarés dans l'en-tête `# plume-emits:` de son capteur.

L'INSTRUMENT SE VALIDE AVANT DE CONCLURE
----------------------------------------
Le faux `date` rend l'heure fixée, l'enveloppe d'outil compte un lancement, la trace `sh -x` d'un script
jouet à boucle GRANDIT avec sa boucle (sinon le témoin structurel ne verrait rien), le corpus et l'attendu
se lisent et portent les quatre réglages. Sans `sh`, `jq`, ni aucun awk, ou sans un fichier livré : code 2.

CE QU'ELLE NE TIENT PAS
-----------------------
· Les compteurs des battements sont dans le MESSAGE, pas dans des champs : un champ neuf doit entrer dans
  l'inventaire de collecte du démon (`daemon/src/collected.rs`), hors de ce changement ; de même, la part
  en liste blanche n'a pas de champ propre (`acq_whitelisted(_delta)` et `acq_parsed(_delta)` la portent).
· Le différentiel prouve l'identité sur CE corpus et ces réglages, pas sur tout journal possible ; il fige
  aussi un défaut hérité (le champ `uid` des SYSCALL vaut l'auid), dit dans l'en-tête du corpus.
· La lecture réelle des journaux (rotation, `kubectl logs`, `cscli` d'une vraie version, `auditctl -l`
  d'un vrai noyau) n'est pas jouée : les sorties simulées ont la forme relevée sur ces outils.
· Seuls les awk présents sont joués ; l'image d'intégration peut n'en porter qu'un.
· Le compte de processus est celui des OUTILS trouvés par `PATH` (enveloppés) : un sous-processus d'awk qui
  n'exécute qu'une commande intégrée du shell (`"true" | getline`, lancé par `/bin/sh -c`) n'est pas compté
  — mutation jouée, restée verte. Un outil par événement, la forme de l'ancien `json_escape`, l'est.
· web : un site sans AUCUNE requête pendant un intervalle de sonde se lit muet — c'est le prix d'un journal
  figé qui ne bat pas, le même que celui d'auditd. Les lignes coupées au plafond dans la seconde du filigrane
  restent PERDUES en k3s : elles sont comptées et avouées, pas rattrapées ; en mode file, l'offset les relit.
  Mode file : au premier passage (ou état de lecture illisible), `tail -n PLUME_WEB_MAX` ne lit pas le début du
  journal — c'est dit dans le battement, pas compté en lignes. Après une rotation perdue (journal relu depuis 0
  sans filigrane), des requêtes déjà publiées peuvent l'être à nouveau : le dédoublonnage `web-<StartUTC>` du
  magasin SQLite (`INSERT OR IGNORE`) les écarte, la garde ne le joue pas. Sous un flot DURABLEMENT
  plus rapide que la borne, l'offset prend du retard sans rien sauter, jusqu'à la rotation — le reste est
  alors lu dans `.1` s'il est là et non compressé, sinon la perte est avouée sans nombre (« peut-être nul » :
  un journal tourné compressé sans `delaycompress` l'avoue à chaque rotation, même lu jusqu'au bout).
  Le journal est reconnu à l'empreinte de sa première ligne : deux journaux dont la première ligne est
  identique octet pour octet seraient confondus. Mode k3s : la perte n'est pas évitée, elle est comptée ; le
  second appel relit jusqu'à 10 × la borne lignes par pod (coût en octets transférés par l'API, pas en mémoire)
  quand la borne est atteinte, et au-delà ne donne qu'un minimum ; seul le `.1` est cherché après une rotation
  (pas `.2`) ;
  le comptage suppose que les pods rendent `--timestamps` au format RFC3339 UTC (`Z`), sinon « nombre
  inconnu » ; plusieurs pods : la borne `--tail` est par pod, le compte est global. Aucun banc ne joue une
  vraie rotation logrotate ni un vrai `kubectl logs`.
· crowdsec : les verdicts de liste blanche jugent les TOTAUX ; une source entièrement en liste blanche parmi
  d'autres qui détectent laisse `lit` (son détail par source le montre). La forme de comptage se déduit de
  `reads` ; un relevé où des lignes lues ne sont pas encore analysées peut la faire mal lire quand la liste
  blanche est presque vide — sans effet sur les verdicts, qui jugent des parts hautes.
· dataaccess : sur une installation qui garde le gabarit livré (`plume_etc` seule), l'aveu des clés de
  données part chaque heure ; c'est exact, aucun accès aux données n'y est observé. Sous l'unité livrée
  (`auditctl` refusé), une clé de données CHARGÉE dont ni le chargement ni un accès ne reste dans
  `audit.log`/`audit.log.1` (rotation sous un flot d'execve) se lit « couverture INCONNUE » jusqu'au premier
  accès : l'erreur part du côté de l'aveu. De même après une RELANCE d'auditd sans redémarrage (le DAEMON_START
  efface les preuves alors que le noyau garde ses règles) ; et une règle chargée AVANT le démarrage d'auditd dont
  le CONFIG_CHANGE serait écrit avant le DAEMON_START serait dite non prouvée — l'ordre réel n'est pas joué sur un
  noyau ici. Une clé portée par plusieurs règles dont une seule est retirée est
  dite non prouvée. Les CONFIG_CHANGE ont la forme relevée dans la documentation du noyau
  (`op=add_rule`/`op=remove_rule`, `res=`), pas sur un noyau joué ici ; une clé écrite en hexadécimal (plusieurs
  clés sur une règle) n'est pas lue, comme avant.
· dataacl : des chemins ABSENTS à côté d'un chemin présent ne sont pas avoués (choix du capteur : la liste
  par défaut vise plusieurs volumes d'un nœud k3s, tous ne sont pas sur chaque nœud) ; seule la TÊTE de
  chaque chemin est sondée (`find -maxdepth 1`) : un sous-répertoire illisible plus bas reste muet. Le cas
  « chemin illisible » n'est pas jouable sous root (un mode 000 ne ferme rien) : il est alors sauté et dit
  sur la sortie. La variable NON posée n'est pas jouée : les défauts sont des chemins absolus de l'hôte
  (`/etc/ssl/private` existe sur la plupart), la branche est la même que la variable posée. Les droits
  réels de l'unité (`CAP_DAC_READ_SEARCH`, `ProtectHome`) ne sont pas joués. La tolérance
  `CESP_AVEU_ANNONCEES` du démon devient inerte (le capteur nomme `dataacl`) mais ne se retire pas d'elle-même.

Sortie : 0 tenu · 1 au moins un défaut · 2 l'instrument REFUSE DE CONCLURE.
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
CAPTEURS = os.path.join(RACINE, "collectors")
LIB = os.path.join(CAPTEURS, "lib.sh")
CORPUS = os.path.join(CAPTEURS, "auditd-differentiel.corpus")
ATTENDU = os.path.join(CAPTEURS, "auditd-differentiel.attendu.json")
HEURE = 1758660000
ETIQUETTE = "check_a_live_sensor_never_reads_as_mute_or_calm"
# Préfixe de trace `sh -x` (PS4). Compté PARTOUT dans la sortie d'erreur, pas en début de ligne : les membres
# d'un tube sont des sous-shells qui tracent EN MÊME TEMPS, leurs lignes s'entrelacent et une ligne de trace
# peut ne pas commencer une ligne (mesuré : 217 à 219 « + » en tête de ligne pour le même passage).
MARQUE_DE_TRACE = "@@trace-c32k@@"
AWK_EXERCES = ("gawk", "mawk")
OUTILS = ["cat", "mktemp", "tail", "wc", "head", "grep", "cksum", "cut", "sed", "tr", "iconv", "chmod", "mv",
          "sync", "rm", "mkdir", "dirname", "basename", "sort", "ls", "env", "printf", "find", "jq", "touch", "uniq"]
REGLAGES = {"defaut": {}, "exec_drop": {"PLUME_AUDITD_EXEC_DROP": "1"},
            "exec_drop_recon": {"PLUME_AUDITD_EXEC_DROP": "1", "PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON": "1"},
            "real_user_only": {"PLUME_AUDIT_REAL_USER_ONLY": "1"}}
ECARTES_ATTENDUS = {"defaut": (0, 0), "exec_drop": (1, 0), "exec_drop_recon": (3, 0), "real_user_only": (0, 1)}
AUDITCTL_REGLES = ("-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -F key=exec_tracking\n"
                   "-w /etc/shadow -p wa -k shadow_changes\n"
                   "-a always,exit -F dir=/etc -F perm=wa -F auid>=1000 -F auid!=-1 -F key=plume_etc\n")

fautes = []


def refus(msg):
    print(f"::error::{ETIQUETTE} : REFUSE DE CONCLURE — {msg}")
    sys.exit(2)


def faute(quoi, msg):
    fautes.append(f"[{quoi}] {msg}")


def ecrire(chemin, texte, executable=False, binaire=False):
    if binaire:
        with open(chemin, "wb") as fh:
            fh.write(texte)
    else:
        with open(chemin, "w", encoding="utf-8", newline="") as fh:
            fh.write(texte)
    if executable:
        os.chmod(chemin, stat.S_IRWXU)


def champs_declares(capteur):
    with open(os.path.join(CAPTEURS, capteur), encoding="utf-8") as fh:
        for ligne in fh:
            m = re.match(r"#\s*plume-emits:\s*fields=(\S*)", ligne)
            if m:
                return set(x for x in m.group(1).split(",") if x)
    return None


class Bac:
    """Un répertoire jetable : outils (vrais liés, ou enveloppés qui se comptent), faux outils, spool, état."""

    def __init__(self, awk, compter=False):
        self.racine = tempfile.mkdtemp(prefix="plume-c32k-")
        self.bin = os.path.join(self.racine, "bin")
        self.faux = os.path.join(self.racine, "faux")
        for d in ("bin", "faux", "spool", "etat", "tmp"):
            os.mkdir(os.path.join(self.racine, d))
        self.compte = os.path.join(self.racine, "compte")
        reels = [(o, shutil.which(o)) for o in OUTILS] + [("awk", awk)]
        for nom, chemin in reels:
            if not chemin:
                continue
            cible = os.path.join(self.bin, nom)
            if compter:
                ecrire(cible, '#!/bin/sh\nprintf "%%s\\n" "%s" >> "$PLUME_GARDE_COMPTE"\nexec \'%s\' "$@"\n'
                       % (nom, chemin), executable=True)
            else:
                os.symlink(chemin, cible)
        date_reel = shutil.which("date")
        ecrire(os.path.join(self.bin, "date"),
               '#!/bin/sh\nif [ "$*" = "+%%s" ]; then echo %d; else exec \'%s\' "$@"; fi\n' % (HEURE, date_reel),
               executable=True)
        self.sh = shutil.which("sh")

    def outil(self, nom, texte):
        ecrire(os.path.join(self.bin, nom), texte, executable=True)

    def retirer(self, nom):
        p = os.path.join(self.bin, nom)
        if os.path.lexists(p):
            os.remove(p)

    def vider_spool(self):
        sp = os.path.join(self.racine, "spool")
        for n in os.listdir(sp):
            os.remove(os.path.join(sp, n))

    def jouer(self, capteur, env_sup=None, trace=False):
        self.vider_spool()
        if os.path.exists(self.compte):
            os.remove(self.compte)
        appels = os.path.join(self.faux, "appels-kubectl")     # le faux `kubectl` compte ses appels PAR passage
        if os.path.exists(appels):
            os.remove(appels)
        env = {"PATH": self.bin, "PLUME_SPOOL": os.path.join(self.racine, "spool"),
               "PLUME_STATE": os.path.join(self.racine, "etat"), "PLUME_LIB": LIB,
               "TMPDIR": os.path.join(self.racine, "tmp"), "LC_ALL": "C.UTF-8", "HOME": self.racine,
               "PLUME_GARDE_COMPTE": self.compte, "FAUX": self.faux, "PS4": MARQUE_DE_TRACE + " "}
        env.update(env_sup or {})
        cmd = [self.sh] + (["-x"] if trace else []) + [os.path.join(CAPTEURS, capteur)]
        r = subprocess.run(cmd, env=env, capture_output=True, timeout=300)
        fichiers = {}
        sp = os.path.join(self.racine, "spool")
        for n in sorted(os.listdir(sp)):
            with open(os.path.join(sp, n), "rb") as fh:
                fichiers[n] = fh.read()
        lances = 0
        if os.path.exists(self.compte):
            with open(self.compte) as fh:
                lances = sum(1 for _ in fh)
        stderr = r.stderr.decode("utf-8", "replace")
        tmp = os.path.join(self.racine, "tmp")
        restes = sorted(os.listdir(tmp))
        for n in restes:
            p = os.path.join(tmp, n)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
        return {"rc": r.returncode, "stderr": stderr, "fichiers": fichiers, "lances": lances,
                "trace": stderr.count(MARQUE_DE_TRACE), "temporaires": restes}

    def nettoyer(self):
        shutil.rmtree(self.racine, ignore_errors=True)


def evenements(quoi, res, capteur):
    """Événements du spool ; un rc non nul, une enveloppe illisible ou un fichier caché sont des fautes."""
    if res["rc"] != 0:
        faute(quoi, f"le capteur sort en {res['rc']} : {res['stderr'].strip()[-300:]}")
    if res.get("temporaires"):
        faute(quoi, f"temporaire(s) laissé(s) dans TMPDIR après le passage : {res['temporaires'][:5]}")
    evs = []
    for nom, brut in res["fichiers"].items():
        if nom.startswith("."):
            faute(quoi, f"fichier caché `{nom}` laissé dans le spool — jamais publié")
            continue
        try:
            doc = json.loads(brut.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            faute(quoi, f"enveloppe `{nom}` illisible ({e}) : tout le passage serait perdu")
            continue
        for ev in doc.get("events") or []:
            ev["_fichier"] = nom
            evs.append(ev)
    declares = champs_declares(capteur) or set()
    for ev in evs:
        if ev.get("category") == "health":
            hors = set(ev.get("fields") or {}) - declares
            if hors:
                faute(quoi, f"champ(s) du battement absents de l'en-tête plume-emits de {capteur} : {sorted(hors)}")
    return evs


def battements(evs, source):
    return [e for e in evs if e.get("source") == source and e.get("category") == "health"]


def aveux(evs, source, statut=None, raison=None):
    out = []
    for e in evs:
        f = e.get("fields") or {}
        if e.get("category") == "config" and f.get("type") == "collector-availability" and f.get("collector") == source:
            if (statut is None or f.get("collect_status") == statut) and (raison is None or f.get("reason") == raison):
                out.append(e)
    return out


def un_battement(quoi, evs, source):
    hb = battements(evs, source)
    if len(hb) != 1:
        faute(quoi, f"{len(hb)} battement(s) source={source} category=health, attendu 1")
        return None
    if "dedup" in hb[0]:
        faute(quoi, "le battement porte une clé de dédoublonnage : il ne s'insérerait qu'une fois")
    return hb[0]


def contient(quoi, texte, *morceaux):
    for m in morceaux:
        if m not in (texte or ""):
            faute(quoi, f"{m!r} absent de {texte!r}")


# --- A. auditd ------------------------------------------------------------------------------------
def lignes_du_corpus():
    with open(CORPUS, encoding="utf-8") as fh:
        return [l for l in fh if not l.startswith("#")]


def decouper(texte):
    """(tête, [(brut, objet)], queue) d'une enveloppe `events`."""
    debut = texte.index('"events":[') + len('"events":[')
    dec, evs, j = json.JSONDecoder(), [], debut
    while texte[j] != "]":
        obj, k = dec.raw_decode(texte, j)
        evs.append((texte[j:k], obj))
        j = k + (1 if texte[k] == "," else 0)
    return texte[:debut], evs, texte[j:]


def comparer_enveloppe(quoi, attendu, obtenu):
    ta, ea, qa = decouper(attendu)
    to, eo, qo = decouper(obtenu)
    if (ta, qa) != (to, qo):
        faute(quoi, f"enveloppe différente : {to[:80]!r}…{qo!r} au lieu de {ta[:80]!r}…{qa!r}")
    na = [b for b, o in ea if o.get("category") != "tamper"]
    no = [b for b, o in eo if o.get("category") != "tamper"]
    if na != no:
        for i, (a, b) in enumerate(zip(na, no)):
            if a != b:
                faute(quoi, f"événement {i} différent :\n    attendu {a}\n    obtenu  {b}")
                break
        else:
            faute(quoi, f"{len(no)} événement(s) hors TAMPER au lieu de {len(na)}")
    ta_ = sorted(b for b, o in ea if o.get("category") == "tamper")
    to_ = sorted(b for b, o in eo if o.get("category") == "tamper")
    if ta_ != to_:
        faute(quoi, f"TAMPER différents : {sorted(set(to_) ^ set(ta_))[:2]}")


def normaliser_hote(brut):
    return re.sub(r'"host":"[^"]*"', '"host":"HOTE"', brut.decode("utf-8"))


def renumeroter(lignes, k):
    return [re.sub(r"audit\((\d+\.\d+):(\d+)\)", lambda m: "audit(%s:%d)" % (m.group(1), int(m.group(2)) + k * 100000), l)
            for l in lignes]


def gardes_par_gravite(evs, place):
    """Les `place` événements que le plafond doit garder : gravité décroissante, les premiers à gravité égale,
    rendus dans l'ordre de la tranche."""
    quota, reste = {}, place
    for sev in sorted({o["severity"] for b, o in evs}, reverse=True):
        quota[sev] = min(reste, sum(1 for b, o in evs if o["severity"] == sev))
        reste -= quota[sev]
    out = []
    for b, o in evs:
        if quota.get(o["severity"], 0) > 0:
            quota[o["severity"]] -= 1
            out.append(b)
    return out


def bac_auditd(awk, compter=False):
    bac = Bac(awk, compter=compter)
    bac.outil("auditctl", "#!/bin/sh\ncat <<'X'\n" + AUDITCTL_REGLES + "X\n")
    return bac


def journal(bac, lignes, nom="audit.log", ajouter=False):
    p = os.path.join(bac.racine, nom)
    with open(p, "ab" if ajouter else "wb") as fh:
        for l in lignes:
            fh.write(l if isinstance(l, bytes) else l.encode("utf-8"))
    return p


def banc_auditd(awk, nom_awk, attendu):
    corpus = lignes_du_corpus()
    ts = str(HEURE)
    # A1 — différentiel, quatre réglages.
    for reglage, env in REGLAGES.items():
        q = f"auditd/{nom_awk}/differentiel/{reglage}"
        bac = bac_auditd(awk)
        try:
            log = journal(bac, corpus)
            res = bac.jouer("auditd.sh", dict(env, PLUME_AUDIT_LOG=log))
            evs = evenements(q, res, "auditd.sh")
            obtenus = {n: normaliser_hote(b) for n, b in res["fichiers"].items()}
            voulus = attendu[reglage]
            for n, texte in voulus.items():
                if n not in obtenus:
                    faute(q, f"`{n}` n'est plus publié")
                elif n.startswith("auditd-") and n != f"auditd-health-{ts}.json":
                    comparer_enveloppe(q, texte, obtenus[n])
                elif obtenus[n] != texte:
                    faute(q, f"`{n}` différent de l'ancienne construction")
            en_plus = set(obtenus) - set(voulus) - {f"auditd-health-{ts}.json"}
            if en_plus:
                faute(q, f"fichier(s) publiés en plus : {sorted(en_plus)}")
            hb = un_battement(q, evs, "auditd")
            if hb:
                emis = len(decouper(voulus[f"auditd-{ts}.json"])[1])
                d, r = ECARTES_ATTENDUS[reglage]
                contient(q, hb.get("message"), f"{len(corpus)} ligne(s) lue(s)", f"{emis} événement(s) émis",
                         f"{d + r} écarté(s) par filtre (exec_drop {d}, real_user_only {r})", "0 au-delà du plafond")
                if hb.get("ts") != HEURE:
                    faute(q, f"battement daté {hb.get('ts')}, attendu l'heure du passage {HEURE}")
            if aveux(evs, "auditd"):
                faute(q, f"aveu de disponibilité émis sous le plafond : {aveux(evs, 'auditd')[0].get('message')}")
            # A4 — journal figé : second passage sans octet neuf, AUCUN battement.
            res = bac.jouer("auditd.sh", dict(env, PLUME_AUDIT_LOG=log))
            evs = evenements(q + "/fige", res, "auditd.sh")
            if battements(evs, "auditd"):
                faute(q + "/fige", "battement émis sur un journal qui n'a pas grossi : le silence d'un auditd arrêté serait couvert")
            if [n for n in res["fichiers"] if n.startswith("auditd-")]:
                faute(q + "/fige", f"publication sur un journal figé : {sorted(res['fichiers'])}")
        finally:
            bac.nettoyer()

    # A3 — tranche neuve sans aucun événement : battement, 0 émis, pas d'enveloppe d'événements.
    q = f"auditd/{nom_awk}/tranche_sans_evenement"
    bac = bac_auditd(awk)
    try:
        sans = [l for l in corpus if "type=SERVICE_START" in l or "type=CRED_DISP" in l]
        if len(sans) != 2:
            refus("le corpus ne porte plus ses deux enregistrements sans intérêt (SERVICE_START, CRED_DISP)")
        log = journal(bac, sans)
        res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log})
        evs = evenements(q, res, "auditd.sh")
        hb = un_battement(q, evs, "auditd")
        if hb:
            contient(q, hb.get("message"), "2 ligne(s) lue(s)", "0 événement(s) émis")
        if [n for n in res["fichiers"] if re.match(r"auditd-\d+\.json$", n)]:
            faute(q, "enveloppe d'événements publiée pour une tranche sans événement")
        # puis la tranche suivante, qui en porte : le battement repart, l'offset a avancé.
        journal(bac, corpus[:1], ajouter=True)
        res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log})
        evs = evenements(q + "/suite", res, "auditd.sh")
        hb = un_battement(q + "/suite", evs, "auditd")
        if hb:
            contient(q + "/suite", hb.get("message"), "1 ligne(s) lue(s)", "1 événement(s) émis")
    finally:
        bac.nettoyer()

    # A5 — plafond bas : TAMPER d'abord, puis par gravité décroissante, dans l'ordre d'avant ; avoué.
    defaut = decouper(attendu["defaut"][f"auditd-{ts}.json"])[1]
    hors_tamper_evs = [(b, o) for b, o in defaut if o["category"] != "tamper"]
    tampers = sorted(b for b, o in defaut if o["category"] == "tamper")
    for cap in (3, len(tampers) + 2, 0):
        q = f"auditd/{nom_awk}/plafond_{cap}"
        bac = bac_auditd(awk)
        try:
            log = journal(bac, corpus)
            res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log, "PLUME_AUDIT_MAX": str(cap)})
            evs = evenements(q, res, "auditd.sh")
            env_evs = res["fichiers"].get(f"auditd-{ts}.json")
            gardes = decouper(normaliser_hote(env_evs))[1] if env_evs else []
            k_t = min(cap, len(tampers))
            k_n = cap - k_t
            if len(gardes) != cap:
                faute(q, f"{len(gardes)} événement(s) publiés, attendu {cap}")
            else:
                if [b for b, o in gardes[:k_n]] != gardes_par_gravite(hors_tamper_evs, k_n):
                    faute(q, "les événements hors TAMPER gardés ne sont pas les plus graves (les premiers à gravité "
                             "égale), dans l'ordre de la tranche")
                if any(o["category"] != "tamper" for b, o in gardes[k_n:]) or \
                        not set(b for b, o in gardes[k_n:]) <= set(tampers):
                    faute(q, "les TAMPER ne sont pas gardés en priorité au plafond")
            ecartes = len(defaut) - cap
            hb = un_battement(q, evs, "auditd")
            if hb:
                contient(q, hb.get("message"), f"{ecartes} au-delà du plafond PLUME_AUDIT_MAX={cap}")
            av = aveux(evs, "auditd", "unavailable", "collection-capped")
            if len(av) != 1:
                faute(q, f"{len(av)} aveu(x) `collection-capped`, attendu 1 — la coupe serait silencieuse")
            else:
                contient(q, (av[0].get("fields") or {}).get("detail"), f"{ecartes} ligne(s)")
            # un passage coupé n'est pas un passage « rien de neuf » : sa configuration de collecte part encore.
            if f"config-auditd-{ts}.json" not in res["fichiers"]:
                faute(q, "configuration de collecte non publiée sur un passage coupé par le plafond")
        finally:
            bac.nettoyer()

    # A5b — ÉVASION PAR SATURATION : une tranche ouverte par un flot d'execve bénins (sev 1), puis un exec en
    # échec (sev 2), un `svc_exec` (sev 3) et un TAMPER, sous un plafond bas. Garder « les premiers » les
    # perdait (l'offset avance) ; trier la SORTIE par gravité changerait l'ordre d'avant. Les deux rougissent.
    q = f"auditd/{nom_awk}/plafond_sature"
    def exec_ligne(serie, comm, succes="yes", auid="1000", cle="exec_tracking"):
        return (f"type=SYSCALL msg=audit(1758650100.{serie:03d}:{7000 + serie}): arch=c000003e syscall=59 "
                f"success={succes} exit=0 items=1 ppid=900 pid={2000 + serie} auid={auid} uid=1000 gid=1000 "
                f"tty=pts0 ses=3 comm=\"{comm}\" exe=\"/usr/bin/{comm}\" key=\"{cle}\"\n")
    benins = [f"b{i:02d}" for i in range(1, 11)]
    sature = [exec_ligne(i, c) for i, c in enumerate(benins, 1)]
    sature.append(exec_ligne(20, "echec", succes="no"))
    sature.append(exec_ligne(21, "svc", auid="4294967295", cle="svc_exec"))
    sature.append("type=SYSCALL msg=audit(1758650100.030:7030): arch=c000003e syscall=257 success=yes exit=3 "
                  "items=2 ppid=900 pid=2030 auid=1000 uid=0 gid=0 tty=pts0 ses=3 comm=\"vi\" exe=\"/usr/bin/vi\" "
                  "key=\"shadow_changes\"\n")
    sature.append("type=PATH msg=audit(1758650100.030:7030): item=1 name=\"/etc/shadow\" inode=9 dev=fd:00 "
                  "mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL\n")
    total = len(benins) + 3
    for cap, voulus in ((5, ["b01", "b02", "echec", "svc", "tamper"]), (3, ["echec", "svc", "tamper"]),
                        (2, ["svc", "tamper"]), (1, ["tamper"])):
        qc = f"{q}_{cap}"
        bac = bac_auditd(awk)
        try:
            log = journal(bac, sature)
            res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log, "PLUME_AUDIT_MAX": str(cap)})
            evs = evenements(qc, res, "auditd.sh")
            env_evs = res["fichiers"].get(f"auditd-{ts}.json")
            gardes = [o for b, o in decouper(normaliser_hote(env_evs))[1]] if env_evs else []
            obtenus = ["tamper" if o.get("category") == "tamper" else (o.get("fields") or {}).get("comm")
                       for o in gardes]
            if obtenus != voulus:
                faute(qc, f"gardés au plafond {obtenus}, attendu {voulus} (TAMPER, puis gravité décroissante, "
                          f"dans l'ordre de la tranche)")
            ecartes = total - cap
            hb = un_battement(qc, evs, "auditd")
            if hb:
                contient(qc, hb.get("message"), f"{ecartes} au-delà du plafond PLUME_AUDIT_MAX={cap}")
            av = aveux(evs, "auditd", "unavailable", "collection-capped")
            if len(av) != 1:
                faute(qc, f"{len(av)} aveu(x) `collection-capped`, attendu 1")
            else:
                contient(qc, (av[0].get("fields") or {}).get("detail"), f"{ecartes} ligne(s)", "gravite decroissante")
        finally:
            bac.nettoyer()

    # A8 — plafond illisible : repli sur le défaut, dit ; la collecte est entière.
    q = f"auditd/{nom_awk}/plafond_illisible"
    bac = bac_auditd(awk)
    try:
        log = journal(bac, corpus)
        res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log, "PLUME_AUDIT_MAX": "beaucoup"})
        evs = evenements(q, res, "auditd.sh")
        n = len([e for e in evs if e["_fichier"] == f"auditd-{ts}.json"])
        if n != len(defaut):
            faute(q, f"{n} événement(s) publiés, attendu {len(defaut)} (repli sur le défaut)")
        if len(aveux(evs, "auditd", "fallback", "unreadable-config")) != 1:
            faute(q, "plafond illisible non avoué (`fallback` / `unreadable-config`)")
    finally:
        bac.nettoyer()

    # A9 — ÉCHECS DE L'ANALYSE : le premier awk, le second, des comptes illisibles. Chacun s'avoue, ne bat
    # pas, ne publie rien, et n'acquitte rien : le passage suivant, sain, rend toute la tranche.
    reel = awk
    for nom, enveloppe, morceau in (
            ("premier_awk", '#!/bin/sh\nfor a; do case "$a" in realonly=*) exit 2 ;; esac; done\nexec \'%s\' "$@"\n' % reel,
             "l'analyse awk de la tranche"),
            ("second_awk", '#!/bin/sh\nfor a; do case "$a" in stats=*) exit 2 ;; esac; done\nexec \'%s\' "$@"\n' % reel,
             "la construction des evenements"),
            ("comptes_illisibles", '#!/bin/sh\nf=\nfor a; do case "$a" in stats=*) f=${a#stats=} ;; esac; done\n'
                                   '\'%s\' "$@" || exit $?\n[ -z "$f" ] || echo "x y" > "$f"\n' % reel,
             "comptes de l'analyse sont illisibles")):
        q = f"auditd/{nom_awk}/echec/{nom}"
        bac = bac_auditd(awk)
        try:
            log = journal(bac, corpus)
            bac.retirer("awk")
            bac.outil("awk", enveloppe)
            res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log})
            evs = evenements(q, res, "auditd.sh")
            av = aveux(evs, "auditd", "unavailable", "missing-source")
            if len(av) != 1:
                faute(q, f"{len(av)} aveu(x) `missing-source`, attendu 1 — l'échec serait muet")
            else:
                contient(q, (av[0].get("fields") or {}).get("detail"), morceau)
            if battements(evs, "auditd"):
                faute(q, "battement émis sur une analyse en échec : le capteur se dirait vivant")
            if f"auditd-{ts}.json" in res["fichiers"]:
                faute(q, "enveloppe d'événements publiée malgré l'échec")
            bac.retirer("awk")
            os.symlink(reel, os.path.join(bac.bin, "awk"))
            res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log})
            evs = evenements(q + "/reprise", res, "auditd.sh")
            n = len([e for e in evs if e["_fichier"] == f"auditd-{ts}.json"])
            if n != len(defaut):
                faute(q + "/reprise", f"{n} événement(s) au passage suivant, attendu {len(defaut)} : la tranche a été acquittée")
        finally:
            bac.nettoyer()

    # A7 — les deux écarts nommés : sans identifiant, contrôle brut, octet UTF-8 invalide.
    q = f"auditd/{nom_awk}/ecarts"
    bac = bac_auditd(awk)
    try:
        sans_id = ('type=USER_AUTH msg=sans-identifiant: pid=1 uid=0 auid=1000 ses=3 msg=\'op=PAM:authentication '
                   'acct="sansid" exe="/usr/sbin/sshd" hostname=? addr=192.0.2.20 terminal=ssh res=failed\'\n')
        controle = ('type=SYSCALL msg=audit(1758650009.111:9001): arch=c000003e syscall=59 success=yes exit=0 items=1 '
                    'ppid=1 pid=2 auid=1000 uid=1000 gid=0 tty=pts0 ses=3 comm="ctl" exe="/usr/bin/a\x01b" '
                    'key="exec_tracking"\n')
        invalide = (b'type=SYSCALL msg=audit(1758650009.222:9002): arch=c000003e syscall=59 success=yes exit=0 items=1 '
                    b'ppid=1 pid=3 auid=1000 uid=1000 gid=0 tty=pts0 ses=3 comm="inv" exe="/usr/bin/a\xffb" '
                    b'key="exec_tracking"\n')
        log = journal(bac, [sans_id, controle, invalide])
        res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log})
        evs = evenements(q, res, "auditd.sh")
        sid = [e for e in evs if (e.get("fields") or {}).get("acct") == "sansid"]
        if len(sid) != 1:
            faute(q, f"enregistrement sans identifiant audit(...) : {len(sid)} événement(s), attendu 1 (il était jeté en silence)")
        elif "dedup" in sid[0] or sid[0].get("src_ip") != "192.0.2.20":
            faute(q, f"enregistrement sans identifiant mal rendu (attendu sans clé, avec src_ip) : {sid[0]}")
        par_comm = {(e.get("fields") or {}).get("comm"): (e.get("fields") or {}).get("exe", "")
                    for e in evs if e.get("category") == "exec"}
        if par_comm.get("ctl") != "/usr/bin/ab":
            faute(q, f"valeur à contrôle brut : exe={par_comm.get('ctl')!r}, attendu le contrôle retiré ('/usr/bin/ab')")
        # L'octet invalide : l'enveloppe est lisible (jugé plus haut) et l'événement est là. La valeur exacte
        # dépend de l'awk — gawk sous une locale UTF-8 arrête la lecture du champ à l'octet invalide, mawk le
        # garde et `iconv -c` le retire ; les deux rendent un préfixe de la valeur, jamais un octet brut.
        if not (par_comm.get("inv") or "").startswith("/usr/bin/a"):
            faute(q, f"valeur à octet UTF-8 invalide : exe={par_comm.get('inv')!r}, attendu un préfixe de '/usr/bin/a…b' sans l'octet")
    finally:
        bac.nettoyer()

    # A6 — STRUCTURE : autant de commandes shell et de processus pour le corpus et pour vingt copies.
    q = f"auditd/{nom_awk}/lineaire"
    comptes = {}
    for copies in (1, 20):
        bac = bac_auditd(awk, compter=True)
        try:
            lignes = [l for k in range(copies) for l in renumeroter(corpus, k)]
            log = journal(bac, lignes)
            res = bac.jouer("auditd.sh", {"PLUME_AUDIT_LOG": log}, trace=True)
            evs = evenements(f"{q}/{copies}", res, "auditd.sh")
            n = len([e for e in evs if e["_fichier"] == f"auditd-{ts}.json"])
            if n != copies * len(defaut):
                faute(f"{q}/{copies}", f"{n} événement(s), attendu {copies * len(defaut)}")
            comptes[copies] = (res["trace"], res["lances"])
        finally:
            bac.nettoyer()
    (t1, l1), (t20, l20) = comptes[1], comptes[20]
    if t1 != t20:
        faute(q, f"commandes shell exécutées : {t1} pour le corpus, {t20} pour vingt copies — le travail shell croît avec le journal")
    if l1 != l20:
        faute(q, f"processus lancés : {l1} pour le corpus, {l20} pour vingt copies — un processus par événement")
    if t1 < 20 or l1 < 3:
        refus(f"le témoin structurel ne compte presque rien (trace {t1}, lancements {l1}) : il ne prouverait rien")


# --- B. web ---------------------------------------------------------------------------------------
def ligne_web(i, chemin, statut=200, seconde=None, fraction=123456789):
    sec = i if seconde is None else seconde
    return ('{"ClientHost":"192.0.2.%d","DownstreamContentSize":12,"DownstreamStatus":%d,"Duration":1500000,'
            '"RequestHost":"site.example.test","RequestMethod":"GET","RequestPath":"%s","RequestProtocol":"HTTP/1.1",'
            '"RouterName":"site@kubernetescrd","StartUTC":"2026-09-23T19:40:%02d.%09dZ","level":"info",'
            '"request_User-Agent":"ua","time":"2026-09-23T21:40:%02d+02:00"}\n'
            % (10 + i % 200, statut, chemin, sec, fraction, sec))


def banc_web(awk, nom_awk):
    q = f"web/{nom_awk}"
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "access.log")
        ecrire(log, ligne_web(1, "/a") + ligne_web(2, "/sante/ping") + "ligne qui n'est pas un journal d'accès\n"
               + ligne_web(3, "/b"))
        env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log, "PLUME_WEB_SKIP_PATH": "/sante"}
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/1", res, "web.sh")
        if len([e for e in evs if e.get("category") == "web"]) != 2:
            faute(q + "/1", "le capteur ne publie plus ses deux requêtes gardées")
        hb = un_battement(q + "/1", evs, "web")
        if hb:
            contient(q + "/1", hb.get("message"), "4 ligne(s) lue(s)", "2 gardée(s)", "1 filtrée(s)", "0 déjà vue(s)",
                     "1 hors journal d'accès", "0 reportée(s) au passage suivant et 0 perdue(s)")
            if hb.get("ts") != HEURE:
                faute(q + "/1", f"battement daté {hb.get('ts')}, attendu {HEURE}")
        # journal FIGÉ : toutes les lignes déjà vues (Traefik arrêté) — AUCUN battement, la sonde doit crier.
        for k in (2, 3):
            res = bac.jouer("web.sh", env)
            evs = evenements(f"{q}/fige{k}", res, "web.sh")
            if battements(evs, "web"):
                faute(f"{q}/fige{k}", "battement émis sur un journal figé : le silence d'un Traefik arrêté serait couvert")
            if [e for e in evs if e.get("category") == "web"]:
                faute(f"{q}/fige{k}", "requêtes republiées alors qu'elles étaient déjà vues")
        # trafic neuf entièrement FILTRÉ : la source vit, le battement part (le cas qui se lisait « capteur mort »).
        with open(log, "a") as fh:
            fh.write(ligne_web(4, "/sante/ping"))
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/filtre_seul", res, "web.sh")
        hb = un_battement(q + "/filtre_seul", evs, "web")
        if hb:
            # P10.33-e — lecture par offset : seule la ligne neuve est lue.
            contient(q + "/filtre_seul", hb.get("message"), "santé : 1 ligne(s) lue(s)", "0 gardée(s)", "1 filtrée(s)",
                     ", 0 déjà vue(s)")
        # la ligne filtrée a fait avancer le filigrane : le même journal, figé, ne bat plus.
        res = bac.jouer("web.sh", env)
        if battements(evenements(q + "/fige_apres_filtre", res, "web.sh"), "web"):
            faute(q + "/fige_apres_filtre", "battement émis sur un journal figé dont la dernière ligne était filtrée")
        # journal TRONQUÉ sur place sans journal tourné retrouvé : ni battement, mais la rotation est avouée (P10.33-e).
        ecrire(log, "")
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/tronque", res, "web.sh")
        if battements(evs, "web"):
            faute(q + "/tronque", "battement émis sur un journal vide")
        av = aveux(evs, "web", "unavailable", "missing-source")
        if len(av) != 1 or "ROTATION" not in ((av[0].get("fields") or {}).get("detail") or ""):
            faute(q + "/tronque", "journal tronqué sans journal tourné : la rotation n'est pas avouée")
        # source vide, jamais lue : ni battement ni aveu.
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/vide", res, "web.sh")
        if battements(evs, "web") or aveux(evs, "web"):
            faute(q + "/vide", "lecture vide : un battement ou un aveu est parti")
        # lecture en échec : aucun battement, un aveu.
        os.remove(log)
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/echec", res, "web.sh")
        if battements(evs, "web"):
            faute(q + "/echec", "battement émis sur une lecture en échec : un capteur aveugle se dirait vivant")
        if len(aveux(evs, "web", "unavailable")) != 1:
            faute(q + "/echec", "lecture en échec non avouée")
        # k3s, sélecteur sans pod : `kubectl logs` rend vide et 0 — aucun battement.
        bac.outil("kubectl", "#!/bin/sh\nexit 0\n")
        res = bac.jouer("web.sh", {"PLUME_WEB_SRC": "k3s"})
        evs = evenements(q + "/k3s_sans_pod", res, "web.sh")
        if battements(evs, "web"):
            faute(q + "/k3s_sans_pod", "battement émis alors qu'aucun pod n'a rendu une ligne")
        bac.retirer("kubectl")
    finally:
        bac.nettoyer()

    # PLAFOND de 9000 requêtes publiées : 9000 gardées, 2 coupées dans la MÊME seconde, 1 coupée dans une seconde
    # postérieure. En k3s (filigrane horaire) : les 2 de la même seconde sont perdues et avouées, la postérieure est
    # reportée. En mode file (P10.33-e) : l'offset s'arrête devant la première ligne coupée, les TROIS sont relues
    # et publiées au passage suivant, rien n'est perdu ni avoué.
    for mode in ("k3s", "file"):
        q = f"web/{nom_awk}/plafond/{mode}"
        bac = Bac(awk)
        try:
            log = os.path.join(bac.racine, "access.log")
            lignes = [ligne_web(i, f"/p{i}", seconde=10, fraction=i) for i in range(9002)]
            lignes.append(ligne_web(9002, "/plus_tard", seconde=11, fraction=1))
            if mode == "file":
                ecrire(log, "".join(lignes))
                env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log}
            else:
                bac.outil("kubectl", FAUX_KUBECTL)
                ecrire(os.path.join(bac.faux, "k3s.log"),
                       "".join("2026-09-23T19:40:%02d.%09dZ %s" % (10 if i < 9002 else 11, i + 1, l) for i, l in enumerate(lignes)))
                env = {"PLUME_WEB_SRC": "k3s"}
            res = bac.jouer("web.sh", env)
            evs = evenements(q + "/1", res, "web.sh")
            n = len([e for e in evs if e.get("category") == "web"])
            if n != 9000:
                faute(q + "/1", f"{n} requête(s) publiées, attendu 9000")
            hb = un_battement(q + "/1", evs, "web")
            av = aveux(evs, "web", "unavailable", "collection-capped")
            if mode == "k3s":
                if hb:
                    contient(q + "/1", hb.get("message"), "9003 ligne(s) lue(s)", "9000 gardée(s)",
                             "1 reportée(s) au passage suivant et 2 perdue(s)")
                if len(av) != 1:
                    faute(q + "/1", f"{len(av)} aveu(x) `collection-capped`, attendu 1 — la perte serait dite « reportée »")
                else:
                    contient(q + "/1", (av[0].get("fields") or {}).get("detail"), "2 ligne(s)")
            else:
                if hb:
                    contient(q + "/1", hb.get("message"), "9003 ligne(s) lue(s)", "9000 gardée(s)",
                             "3 reportée(s) au passage suivant et 0 perdue(s)")
                if av:
                    faute(q + "/1", "perte avouée en mode file : l'offset relit pourtant toutes les lignes coupées")
            res = bac.jouer("web.sh", env)
            evs = evenements(q + "/2", res, "web.sh")
            pub = publiees(evs)
            attendu = ["/plus_tard"] if mode == "k3s" else ["/p9000", "/p9001", "/plus_tard"]
            if pub != attendu:
                faute(q + "/2", f"publiées au passage suivant : {pub}, attendu {attendu}")
            hb = un_battement(q + "/2", evs, "web")
            if hb:
                if mode == "k3s":
                    contient(q + "/2", hb.get("message"), ", 1 gardée(s)", "9002 déjà vue(s)",
                             "0 reportée(s) au passage suivant et 0 perdue(s)")
                else:
                    contient(q + "/2", hb.get("message"), "santé : 3 ligne(s) lue(s)", ", 3 gardée(s)", ", 0 déjà vue(s)",
                             "0 reportée(s) au passage suivant et 0 perdue(s)")
            if aveux(evs, "web", "unavailable", "collection-capped"):
                faute(q + "/2", "aveu de perte émis sous le plafond")
        finally:
            bac.nettoyer()

    # PLAFOND PUIS LIGNE FILTRÉE : 9000 gardées à la seconde 10, `/plus_tard` coupée à la seconde 11, puis
    # `/sante/ping` FILTRÉE à la seconde 12. La ligne filtrée ne doit pas pousser le filigrane au-delà de la
    # ligne coupée : `/plus_tard` est dite reportée, publiée au passage suivant, et rien n'est avoué perdu.
    q = f"web/{nom_awk}/plafond_puis_filtre"
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "access.log")
        lignes = [ligne_web(i, f"/p{i}", seconde=10, fraction=i) for i in range(9000)]
        lignes.append(ligne_web(9000, "/plus_tard", seconde=11, fraction=1))
        lignes.append(ligne_web(9001, "/sante/ping", seconde=12, fraction=1))
        ecrire(log, "".join(lignes))
        env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log, "PLUME_WEB_SKIP_PATH": "/sante"}
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/1", res, "web.sh")
        hb = un_battement(q + "/1", evs, "web")
        if hb:
            contient(q + "/1", hb.get("message"), "9000 gardée(s)", "1 filtrée(s)",
                     "1 reportée(s) au passage suivant et 0 perdue(s)")
        if aveux(evs, "web", "unavailable", "collection-capped"):
            faute(q + "/1", "perte avouée : la ligne filtrée a poussé le filigrane au-delà d'une ligne coupée")
        res = bac.jouer("web.sh", env)
        evs = evenements(q + "/2", res, "web.sh")
        pub = [e for e in evs if e.get("category") == "web"]
        if len(pub) != 1 or "/plus_tard" not in pub[0].get("message", ""):
            faute(q + "/2", "la ligne coupée avant une ligne filtrée n'est pas publiée au passage suivant : "
                  f"{[e.get('message') for e in pub]}")
    finally:
        bac.nettoyer()

    # BORNE DE LECTURE PLUME_WEB_MAX atteinte : dite dans le battement.
    q = f"web/{nom_awk}/borne_de_lecture"
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "access.log")
        ecrire(log, "".join(ligne_web(i, f"/l{i}") for i in range(1, 5)))
        res = bac.jouer("web.sh", {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log, "PLUME_WEB_MAX": "3"})
        hb = un_battement(q, evenements(q, res, "web.sh"), "web")
        if hb:
            contient(q, hb.get("message"), "3 ligne(s) lue(s)", "borne de lecture PLUME_WEB_MAX=3 atteinte",
                     "premier passage", "ne sont pas lus")
            # P10.33-e — au premier passage, `tail -n MAX` saute le début du journal : le battement ne dit pas le contraire.
            if "rien n'est sauté" in (hb.get("message") or ""):
                faute(q, f"premier passage dit « rien n'est sauté » alors que le début du journal n'est pas lu : {hb.get('message')!r}")
    finally:
        bac.nettoyer()
    banc_web_borne_de_lecture(awk, nom_awk)


# P10.33-e — LA BORNE DE LECTURE NE FAIT PLUS PERDRE EN SILENCE. Mode file : offset d'octets, rien n'est sauté, une
# rotation reprend le journal tourné ; mode k3s : les lignes sorties de la fenêtre `--tail` sont comptées et avouées.
def publiees(evs):
    return [e.get("fields", {}).get("path") for e in evs if e.get("category") == "web"]


def ligne_k3s(i, chemin, statut=200, fraction="123456789", seconde=None):
    sec = i if seconde is None else seconde
    return "2026-09-23T19:40:%02d.%sZ %s" % (sec, fraction, ligne_web(i, chemin, statut, seconde=sec))


# Faux `kubectl logs`, FIDÈLE au vrai sur ce que le capteur en attend : un journal par pod (`k3s.log`, ou
# `pod-*.log`), mis BOUT À BOUT dans l'ordre des pods ; `--tail=N` rend les N dernières lignes DE CHAQUE pod, et
# SANS `--tail`, un sélecteur `-l` en rend 10 par pod (`kubectl logs --help` : « --tail=-1 … Defaults to -1 with
# no selector, showing all log lines otherwise 10, if a selector is provided »), `--tail=-1` toutes. Le premier
# appel d'un passage voit le journal tel qu'écrit ; un appel suivant (le comptage) voit en plus `<pod>.apres`
# (lignes arrivées entre deux appels), ou `<pod>.comptage` À LA PLACE du journal (journal du pod tourné par le
# kubelet entre les deux appels), et échoue si `comptage-en-echec` existe. L'horodatage runtime n'est rendu que
# sous `--timestamps`, comme le vrai.
FAUX_KUBECTL = r"""#!/bin/sh
echo "$*" >> "$FAUX/appels-kubectl"
napp=$(wc -l < "$FAUX/appels-kubectl")
hdt=0; case " $* " in *" --timestamps "*) hdt=1 ;; esac
sortie() { if [ "$hdt" = 1 ]; then cat; else sed 's/^[^{]*//'; fi; }
n=""; for a in "$@"; do case "$a" in --tail=*) n=${a#--tail=} ;; esac; done
if [ -z "$n" ]; then case " $* " in *" -l "*) n=10 ;; *) n=-1 ;; esac; fi
if [ "$napp" -gt 1 ] && [ -f "$FAUX/comptage-en-echec" ]; then exit 1; fi
pod() {
  _src=$1; [ "$napp" -gt 1 ] && [ -f "${1%.log}.comptage" ] && _src=${1%.log}.comptage
  cat "$_src"; if [ "$napp" -gt 1 ] && [ -f "${1%.log}.apres" ]; then cat "${1%.log}.apres"; fi
}
for p in "$FAUX"/k3s.log "$FAUX"/pod-*.log; do
  [ -f "$p" ] || continue
  if [ "$n" = -1 ]; then pod "$p"; else pod "$p" | tail -n "$n"; fi
done | sortie
"""


def banc_web_borne_de_lecture(awk, nom_awk):
    def passages(bac, env, k, quoi):
        vus = []
        for j in range(k):
            res = bac.jouer("web.sh", env)
            evs = evenements(f"{quoi}/{j + 1}", res, "web.sh")
            vus.append((publiees(evs), evs))
        return vus

    # FLOT : un passage voit 2 lignes, puis 5 requêtes réelles noyées dans 6 sondages filtrés arrivent avant le
    # suivant, borne 3. Ancienne lecture `tail -n 3` : seules les 3 dernières lignes lues, le reste perdu sans compte.
    q = f"web/{nom_awk}/flot_fichier"
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "access.log")
        env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log, "PLUME_WEB_MAX": "3", "PLUME_WEB_SKIP_PATH": "/sante"}
        ecrire(log, ligne_web(1, "/r1") + ligne_web(2, "/r2"))
        bac.jouer("web.sh", env)
        flot, i = [], 3
        for k in range(5):
            flot.append(ligne_web(i, f"/r{i}")); i += 1
            if k < 3:
                flot.append(ligne_web(i, "/sante/a")); i += 1
                flot.append(ligne_web(i, "/sante/b")); i += 1
        with open(log, "a") as fh:
            fh.write("".join(flot))
        attendu = [f"/r{n}" for n in range(3, i) if any(f'"/r{n}"' in l for l in flot)]
        vus = passages(bac, env, 6, q)
        tout = [p for pub, _ in vus for p in pub]
        if sorted(tout) != sorted(attendu):
            faute(q, f"requêtes publiées sur six passages : {tout}, attendu {attendu} — des lignes ont été sautées")
        hb = un_battement(q + "/1", vus[0][1], "web")
        if hb:
            contient(q + "/1", hb.get("message"), "santé : 3 ligne(s) lue(s)", "borne de lecture PLUME_WEB_MAX=3 atteinte",
                     "restent à lire, repris au passage suivant", "rien n'est sauté")
        for _, evs in vus:
            if aveux(evs, "web"):
                faute(q, "aveu émis alors que rien n'est perdu")
    finally:
        bac.nettoyer()

    # ÉCRITURE EN COURS : une dernière ligne sans fin de ligne n'est ni lue ni passée par l'offset.
    q = f"web/{nom_awk}/ligne_incomplete"
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "access.log")
        entiere = ligne_web(2, "/partielle")
        ecrire(log, ligne_web(1, "/r1") + entiere[:-40])
        env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log}
        (p1, _), = passages(bac, env, 1, q + "/a")
        with open(log, "a") as fh:
            fh.write(entiere[-40:])
        (p2, _), = passages(bac, env, 1, q + "/b")
        if p1 != ["/r1"] or p2 != ["/partielle"]:
            faute(q, f"ligne en cours d'écriture : publiées {p1} puis {p2}, attendu ['/r1'] puis ['/partielle']")
    finally:
        bac.nettoyer()

    # ROTATIONS : renommage (le reste est lu dans `.1`), copytruncate (idem, `.1` est une copie), journal remplacé
    # par un autre plus long que l'offset (empreinte différente : lu depuis 0), et `.1` introuvable (perte avouée).
    for forme in ("renomme", "copytruncate", "remplace", "introuvable"):
        q = f"web/{nom_awk}/rotation_{forme}"
        bac = Bac(awk)
        try:
            log = os.path.join(bac.racine, "access.log")
            env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log}
            ecrire(log, ligne_web(1, "/r1") + ligne_web(2, "/r2"))
            bac.jouer("web.sh", env)
            if forme in ("renomme", "copytruncate", "introuvable"):
                with open(log, "a") as fh:
                    fh.write(ligne_web(3, "/r3"))
                if forme == "renomme":
                    os.rename(log, log + ".1")
                elif forme == "copytruncate":
                    shutil.copyfile(log, log + ".1")
                else:
                    os.remove(log)
                ecrire(log, ligne_web(4, "/r4"))
                attendu = ["/r4"] if forme == "introuvable" else ["/r3", "/r4"]
            else:
                ecrire(log, "".join(ligne_web(i, f"/n{i}") for i in range(3, 7)))
                attendu = ["/n3", "/n4", "/n5", "/n6"]
            vus = passages(bac, env, 3, q)
            tout = [p for pub, _ in vus for p in pub]
            if tout != attendu:
                faute(q, f"publiées après rotation : {tout}, attendu {attendu}")
            rot = [e for _, evs in vus for e in aveux(evs, "web", "unavailable", "missing-source")
                   if "ROTATION" in ((e.get("fields") or {}).get("detail") or "")]
            if forme in ("renomme", "copytruncate") and rot:
                faute(q, "rotation avouée perdue alors que le journal tourné a été lu")
            if forme in ("introuvable", "remplace") and len(rot) != 1:
                faute(q, f"{len(rot)} aveu(x) de rotation, attendu 1 : le reste du journal précédent n'a pas été lu")
        finally:
            bac.nettoyer()

    # k3s : `kubectl logs --tail` ne rend que les dernières lignes ; les plus anciennes de la fenêtre sont COMPTÉES
    # (second appel, à `--tail` explicite, borné à l'horodatage runtime le plus récent des lignes lues) et avouées.
    for cas in ("compte", "comptage_en_echec", "sous_la_borne"):
        q = f"web/{nom_awk}/flot_k3s/{cas}"
        bac = Bac(awk)
        try:
            bac.outil("kubectl", FAUX_KUBECTL)
            n = 3 if cas == "sous_la_borne" else 10
            # fraction tronquée par RFC3339Nano sur la dernière ligne lue ; les deux lignes arrivées APRÈS la première
            # lecture (même seconde, fraction plus grande une fois complétée à 9 chiffres) ne doivent pas être comptées.
            lignes = [ligne_k3s(i, f"/k{i}") for i in range(1, n)] + [ligne_k3s(n, f"/k{n}", fraction="5")]
            ecrire(os.path.join(bac.faux, "k3s.log"), "".join(lignes))
            ecrire(os.path.join(bac.faux, "k3s.apres"),
                   ligne_k3s(n + 1, "/apres1", fraction="50001", seconde=n) + ligne_k3s(n + 2, "/apres2", fraction="6", seconde=n))
            if cas == "comptage_en_echec":
                ecrire(os.path.join(bac.faux, "comptage-en-echec"), "")
            res = bac.jouer("web.sh", {"PLUME_WEB_SRC": "k3s", "PLUME_WEB_MAX": "4"})
            evs = evenements(q, res, "web.sh")
            pub = publiees(evs)
            av = aveux(evs, "web", "unavailable", "collection-capped")
            hb = un_battement(q, evs, "web")
            try:
                with open(os.path.join(bac.faux, "appels-kubectl")) as fh:
                    appels = [l for l in fh.read().splitlines() if " logs " in f" {l} "]
            except OSError:
                appels = []
            if len(appels) != (1 if cas == "sous_la_borne" else 2):
                faute(q, f"{len(appels)} appel(s) `kubectl logs`, attendu {1 if cas == 'sous_la_borne' else 2} : {appels}")
            elif cas == "compte":
                # le comptage couvre AU MOINS la fenêtre lue : sa fenêtre `--since` est plus large que celle de la lecture.
                fen = [re.search(r"--since=([0-9]+)s", a) for a in appels]
                if not all(fen) or int(fen[1].group(1)) <= int(fen[0].group(1)):
                    faute(q, f"fenêtre du comptage pas plus large que celle de la lecture : {appels}")
            if cas == "sous_la_borne":
                if pub != ["/k1", "/k2", "/k3"] or av:
                    faute(q, f"sous la borne : publiées {pub}, {len(av)} aveu(x)")
                continue
            if pub != ["/k7", "/k8", "/k9", "/k10"]:
                faute(q, f"publiées {pub}, attendu les quatre dernières")
            attendu = ": 6 ligne(s) écartée(s)" if cas == "compte" else ": nombre inconnu écartée(s)"
            if len(av) != 1:
                faute(q, f"{len(av)} aveu(x) `collection-capped`, attendu 1 — les lignes sautées seraient muettes")
            else:
                contient(q, (av[0].get("fields") or {}).get("detail"), attendu, "PLUME_WEB_MAX=4")
            if hb:
                contient(q, hb.get("message"), "borne de lecture PLUME_WEB_MAX=4 atteinte",
                         "atteinte : 6 ligne(s) plus ancienne(s)" if cas == "compte" else "atteinte : nombre inconnu de ligne(s) plus ancienne(s)")
        finally:
            bac.nettoyer()


    # LIGNES HORS JOURNAL D'ACCÈS dans la fenêtre `--tail` (démarrage du pod) : elles ne sont pas des requêtes lues ;
    # le compte des sautées soustrait les requêtes NEUVES lues, pas les lignes lues.
    q = f"web/{nom_awk}/flot_k3s/hors_journal"
    bac = Bac(awk)
    try:
        bac.outil("kubectl", FAUX_KUBECTL)
        lignes = [ligne_k3s(i, f"/k{i}") for i in range(1, 11)]
        lignes.insert(9, '2026-09-23T19:40:10.100000000Z time="x" level=info msg="Configuration loaded"\n')
        lignes.insert(9, '2026-09-23T19:40:09.900000000Z time="x" level=info msg="Starting provider"\n')
        # porte un StartUTC mais pas de DownstreamStatus : la lecture ne la tient pas pour une requête, le comptage non plus.
        lignes.insert(0, '2026-09-23T19:40:00.500000000Z {"StartUTC":"2026-09-23T19:40:00.5Z","level":"info"}\n')
        ecrire(os.path.join(bac.faux, "k3s.log"), "".join(lignes))
        evs = evenements(q, bac.jouer("web.sh", {"PLUME_WEB_SRC": "k3s", "PLUME_WEB_MAX": "4"}), "web.sh")
        if publiees(evs) != ["/k9", "/k10"]:
            faute(q, f"publiées {publiees(evs)}, attendu ['/k9', '/k10']")
        av = aveux(evs, "web", "unavailable", "collection-capped")
        if len(av) != 1:
            faute(q, f"{len(av)} aveu(x) `collection-capped`, attendu 1")
        else:
            contient(q, (av[0].get("fields") or {}).get("detail"), ": 8 ligne(s) écartée(s)")
    finally:
        bac.nettoyer()

    # k3s, CE QUE LE COMPTAGE NE DOIT PAS TAIRE (P10.33-e) :
    #  · cent_lignes — 100 requêtes, borne 20 : 80 sautées. Un comptage sans `--tail` reçoit 10 lignes par pod d'un
    #    vrai `kubectl logs -l` et disait « 0 ligne sautée » ;
    #  · comptage_borne — 60 requêtes, borne 4 : le comptage, borné à 40 lignes par pod, n'en voit que 40 ; le nombre
    #    est un MINIMUM, dit « au moins 36 », jamais un compte exact ;
    #  · pod_tourne — le journal du pod tourne entre les deux appels : le comptage voit moins de requêtes que la
    #    lecture n'en a lu ; « nombre inconnu », jamais un 0 silencieux ;
    #  · deux_pods — `kubectl` met les pods BOUT À BOUT : la dernière ligne lue est celle du dernier pod, pas la plus
    #    récente ; la borne du comptage est le MAX des horodatages lus (6 sautées du premier pod) ;
    #  · apres_filigrane — au second passage, les requêtes déjà vues (sous le filigrane) ne sont pas des sautées ;
    #  · non_z / non_z_deja_vues — horodatages runtime hors `Z` : « nombre inconnu », que des requêtes neuves aient
    #    été lues ou non.
    for cas in ("cent_lignes", "comptage_borne", "pod_tourne", "deux_pods", "apres_filigrane", "non_z", "non_z_deja_vues"):
        q = f"web/{nom_awk}/flot_k3s/{cas}"
        bac = Bac(awk)
        try:
            bac.outil("kubectl", FAUX_KUBECTL)
            k3s = os.path.join(bac.faux, "k3s.log")
            maxi, attendu = "4", None
            if cas == "cent_lignes":
                ecrire(k3s, "".join(ligne_k3s(i, f"/c{i}", seconde=10, fraction="%09d" % (i + 1)) for i in range(100)))
                maxi, attendu = "20", "80"
            elif cas == "comptage_borne":
                ecrire(k3s, "".join(ligne_k3s(i, f"/c{i}", seconde=10, fraction="%09d" % (i + 1)) for i in range(60)))
                attendu = "au moins 36"
            elif cas == "pod_tourne":
                lignes = [ligne_k3s(i, f"/k{i}") for i in range(1, 11)]
                ecrire(k3s, "".join(lignes))
                ecrire(os.path.join(bac.faux, "k3s.comptage"), "".join(lignes[-2:]))
            elif cas == "deux_pods":
                os.remove(k3s) if os.path.exists(k3s) else None
                ecrire(os.path.join(bac.faux, "pod-a.log"), "".join(ligne_k3s(i, f"/a{i}") for i in range(10, 20)))
                ecrire(os.path.join(bac.faux, "pod-b.log"), "".join(ligne_k3s(i, f"/b{i}") for i in range(1, 4)))
                attendu = "6"
            elif cas == "apres_filigrane":
                ecrire(k3s, "".join(ligne_k3s(i, f"/v{i}") for i in range(1, 4)))
                bac.jouer("web.sh", {"PLUME_WEB_SRC": "k3s", "PLUME_WEB_MAX": "10"})
                ecrire(k3s, "".join(ligne_k3s(i, f"/v{i}") for i in range(1, 14)))
                attendu = "6"
            else:
                ecrire(k3s, "".join(ligne_k3s(i, f"/t{i}").replace(".123456789Z ", ".123456789+00:00 ", 1)
                                    for i in range(1, 11)))
                if cas == "non_z_deja_vues":
                    bac.jouer("web.sh", {"PLUME_WEB_SRC": "k3s", "PLUME_WEB_MAX": "20"})
            evs = evenements(q, bac.jouer("web.sh", {"PLUME_WEB_SRC": "k3s", "PLUME_WEB_MAX": maxi}), "web.sh")
            av = aveux(evs, "web", "unavailable", "collection-capped")
            if len(av) != 1:
                faute(q, f"{len(av)} aveu(x) `collection-capped`, attendu 1 — des lignes sautées seraient muettes")
                continue
            detail = (av[0].get("fields") or {}).get("detail") or ""
            if attendu is None or attendu.startswith("au moins"):
                contient(q, detail, ": nombre inconnu écartée(s)")
                dit = f"atteinte : {attendu or 'nombre inconnu de'} ligne(s) plus ancienne(s)"
                contient(q, detail, dit.replace("atteinte", "(kubectl logs --tail)"))
                if attendu:
                    contient(q, detail, "comptage borné à 40 lignes par pod")
            else:
                contient(q, detail, f": {attendu} ligne(s) écartée(s)")
                dit = f"atteinte : {attendu} ligne(s) plus ancienne(s)"
            hb = battements(evs, "web")
            if hb:
                contient(q, hb[0].get("message"), dit)
        finally:
            bac.nettoyer()

    # SECONDE COUPÉE PAR LA BORNE (mode file) : cinq requêtes à la seconde 5, une à la seconde 6, borne 3. Le filigrane
    # horaire appliqué par-dessus l'offset disait « déjà vues » la fin de la seconde 5 et la perdait sans aveu. Et une
    # requête LONGUE, écrite par Traefik à sa fin avec un StartUTC antérieur au filigrane, n'est pas « déjà vue ».
    for cas in ("seconde_coupee", "requete_longue"):
        q = f"web/{nom_awk}/{cas}"
        bac = Bac(awk)
        try:
            log = os.path.join(bac.racine, "access.log")
            env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log, "PLUME_WEB_MAX": "3"}
            ecrire(log, ligne_web(1, "/r1", seconde=1 if cas == "seconde_coupee" else 30))
            bac.jouer("web.sh", env)
            if cas == "seconde_coupee":
                ajout = [ligne_web(10 + k, f"/s5{c}", seconde=5, fraction=k + 1) for k, c in enumerate("abcde")]
                ajout.append(ligne_web(20, "/s6", seconde=6))
            else:
                ajout = [ligne_web(2, "/longue", seconde=12)]
            with open(log, "a") as fh:
                fh.write("".join(ajout))
            attendu = ["/s5a", "/s5b", "/s5c", "/s5d", "/s5e", "/s6"] if cas == "seconde_coupee" else ["/longue"]
            vus = passages(bac, env, 3, q)
            tout = [p for pub, _ in vus for p in pub]
            if tout != attendu:
                faute(q, f"publiées sur trois passages : {tout}, attendu {attendu} — des lignes jamais lues dites déjà vues")
            for j, (_, evs) in enumerate(vus):
                hb = battements(evs, "web")
                if hb and ", 0 déjà vue(s)" not in (hb[0].get("message") or ""):
                    faute(f"{q}/{j + 1}", f"lignes lues après l'offset dites déjà vues : {hb[0].get('message')!r}")
                if aveux(evs, "web"):
                    faute(f"{q}/{j + 1}", "aveu émis alors que rien n'est perdu")
        finally:
            bac.nettoyer()

    # BORNE ATTEINTE PILE : le battement ne dit pas « au moins 0 octet(s) restent à lire ».
    q = f"web/{nom_awk}/borne_pile"
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "access.log")
        env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log, "PLUME_WEB_MAX": "3"}
        ecrire(log, ligne_web(1, "/r1"))
        bac.jouer("web.sh", env)
        with open(log, "a") as fh:
            fh.write("".join(ligne_web(i, f"/r{i}") for i in (2, 3, 4)))
        (pub, evs), = passages(bac, env, 1, q)
        hb = un_battement(q, evs, "web")
        if hb:
            contient(q, hb.get("message"), "PLUME_WEB_MAX=3 atteinte pile", "rien n'est sauté")
            if "au moins 0 octet" in (hb.get("message") or ""):
                faute(q, f"borne atteinte pile dite « au moins 0 octet(s) restent » : {hb.get('message')!r}")
    finally:
        bac.nettoyer()

    # ROTATIONS DE BORD (P10.33-e) :
    #  · creation — `logrotate create` : le journal tourné est lu jusqu'au bout pendant que le neuf est VIDE ; quand le
    #    neuf se remplit, ce n'est pas une rotation perdue (rien n'y avait été lu) ;
    #  · pendant_ecriture — rotation au milieu d'une écriture : la dernière ligne du journal TOURNÉ, sans fin de
    #    ligne, est lue (personne ne l'achèvera), sans quoi l'offset resterait sur `.1` et le neuf ne serait plus lu ;
    #  · plus_court — même première ligne, fichier plus court que l'offset (tronqué puis réécrit) : rotation, lu
    #    depuis 0, perte avouée ; le prendre pour le même journal ne lirait plus rien.
    for forme in ("creation", "pendant_ecriture", "plus_court"):
        q = f"web/{nom_awk}/rotation_{forme}"
        bac = Bac(awk)
        try:
            log = os.path.join(bac.racine, "access.log")
            env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log}
            if forme == "plus_court":
                ecrire(log, ligne_web(1, "/r1") + ligne_web(2, "/r2") + ligne_web(3, "/r3"))
            else:
                ecrire(log, ligne_web(1, "/r1"))
            bac.jouer("web.sh", env)
            vus = []
            if forme == "creation":
                with open(log, "a") as fh:
                    fh.write(ligne_web(2, "/r2"))
                os.rename(log, log + ".1")
                ecrire(log, "")
                vus += passages(bac, env, 1, q + "/a")
                with open(log, "a") as fh:
                    fh.write(ligne_web(3, "/r3"))
                vus += passages(bac, env, 2, q + "/b")
                attendu, n_rot = [["/r2"], ["/r3"], []], 0
            elif forme == "pendant_ecriture":
                with open(log, "a") as fh:
                    fh.write(ligne_web(2, "/r2") + ligne_web(3, "/coupee")[:-40])
                os.rename(log, log + ".1")
                ecrire(log, ligne_web(4, "/r4"))
                vus += passages(bac, env, 3, q)
                attendu, n_rot = [["/r2", "/coupee"], ["/r4"], []], 0
            else:
                ecrire(log, ligne_web(1, "/r1") + ligne_web(4, "/r4"))
                vus += passages(bac, env, 2, q)
                attendu, n_rot = None, 1
            pubs = [pub for pub, _ in vus]
            rot = [e for _, evs in vus for e in aveux(evs, "web", "unavailable", "missing-source")
                   if "ROTATION" in ((e.get("fields") or {}).get("detail") or "")]
            if attendu is not None and pubs != attendu:
                faute(q, f"publiées par passage : {pubs}, attendu {attendu}")
            if attendu is None and ("/r4" not in pubs[0] or pubs[1]):
                faute(q, f"publiées par passage : {pubs}, attendu `/r4` au premier (relu depuis 0), rien au second")
            if len(rot) != n_rot:
                faute(q, f"{len(rot)} aveu(x) de rotation, attendu {n_rot}")
        finally:
            bac.nettoyer()

    # ROTATIONS DONT LE `.1` N'EST PAS LE JOURNAL LU (P10.33-e) :
    #  · double — deux rotations entre deux passages : le journal lu est devenu `.2`, `.1` est un journal postérieur ;
    #    le lire depuis l'offset de l'autre publierait le milieu d'un journal et tairait la perte ;
    #  · tourne_plus_court — `.1` a la même première ligne mais est plus court que l'offset : ce n'est pas le journal
    #    lu ; le prendre pour lui ne lirait rien et tairait la perte.
    for forme in ("double", "tourne_plus_court"):
        q = f"web/{nom_awk}/rotation_{forme}"
        bac = Bac(awk)
        try:
            log = os.path.join(bac.racine, "access.log")
            env = {"PLUME_WEB_SRC": "file", "PLUME_WEB_LOG": log}
            if forme == "double":
                ecrire(log, ligne_web(1, "/a1") + ligne_web(2, "/a2"))
                bac.jouer("web.sh", env)
                os.rename(log, log + ".2")
                ecrire(log + ".1", "".join(ligne_web(i, f"/b{i}") for i in range(3, 8)))
                ecrire(log, ligne_web(8, "/c8"))
                attendu = [["/c8"], []]
            else:
                ecrire(log, ligne_web(1, "/r1") + ligne_web(2, "/r2") + ligne_web(3, "/r3"))
                bac.jouer("web.sh", env)
                os.remove(log)
                ecrire(log + ".1", ligne_web(1, "/r1"))
                ecrire(log, ligne_web(4, "/n4"))
                attendu = [["/n4"], []]
            vus = []
            for j in range(2):
                evs = evenements(f"{q}/{j + 1}", bac.jouer("web.sh", env), "web.sh")
                vus.append((publiees(evs), evs))
            pubs = [pub for pub, _ in vus]
            rot = [e for _, evs in vus for e in aveux(evs, "web", "unavailable", "missing-source")
                   if "ROTATION" in ((e.get("fields") or {}).get("detail") or "")]
            if pubs != attendu:
                faute(q, f"publiées par passage : {pubs}, attendu {attendu}")
            if len(rot) != 1 or not aveux(vus[0][1], "web", "unavailable", "missing-source"):
                faute(q, f"{len(rot)} aveu(x) de rotation, attendu 1 au premier passage : la perte serait tue")
        finally:
            bac.nettoyer()

# --- C. crowdsec ----------------------------------------------------------------------------------
FAUX_CSCLI = r"""#!/bin/sh
case "$*" in
  "alerts list --limit 0 -o json") printf '[]' ;;
  "hub list -o json") printf '{"scenarios":[{"name":"a"},{"name":"b"}]}' ;;
  "metrics show acquisition -o json") cat "$FAUX/metrics" ;;
  "metrics -o json") cat "$FAUX/metrics" ;;
  *) exit 1 ;;
esac
"""
SRC = "file:/var/log/containers/web-a.log"


def acq(reads, parsed, unparsed, pour, wl):
    return json.dumps({"acquisition": {SRC: {"reads": reads, "parsed": parsed, "unparsed": unparsed,
                                             "pour": pour, "whitelisted": wl}}})


SAIN = acq(1000, 900, 100, 7, 88)


def banc_crowdsec(awk):
    def passage(bac, metrics, env=None):
        ecrire(os.path.join(bac.faux, "metrics"), metrics)
        res = bac.jouer("crowdsec.sh", dict({"PLUME_CSCLI": os.path.join(bac.bin, "cscli")}, **(env or {})))
        return res, evenements("crowdsec", res, "crowdsec.sh")

    def etat(bac):
        p = os.path.join(bac.racine, "etat", "crowdsec-acquisition.json")
        return open(p).read() if os.path.exists(p) else None

    def acquisition(evs):
        return [e for e in aveux(evs, "crowdsec", "unavailable")
                if "acquisition CrowdSec" in ((e.get("fields") or {}).get("detail") or "")]

    def refus_lb(q, evs, avant, bac):
        hb = un_battement(q, evs, "crowdsec")
        if not hb:
            return
        f = hb.get("fields") or {}
        if f.get("acq_verdict") != "tout_en_liste_blanche":
            faute(q, f"acq_verdict={f.get('acq_verdict')!r}, attendu 'tout_en_liste_blanche'")
        if hb.get("severity", 0) < 3:
            faute(q, f"sévérité {hb.get('severity')} : un refus de conclure la relève à 3")
        contient(q, hb.get("message"), "ACQUISITION tout_en_liste_blanche :", "mandataire")
        av = acquisition(evs)
        if len(av) != 1:
            faute(q, f"{len(av)} aveu(x) d'acquisition, attendu 1")
        else:
            contient(q, av[0]["fields"].get("detail"), "(forme_inconnue)", "tout_en_liste_blanche", "mandataire")
        if etat(bac) != avant:
            faute(q, "l'état d'acquisition a avancé sur un refus de conclure")

    def sans_refus(q, evs, verdict, sev, *morceaux):
        hb = un_battement(q, evs, "crowdsec")
        if not hb:
            return
        f = hb.get("fields") or {}
        if f.get("acq_verdict") != verdict:
            faute(q, f"acq_verdict={f.get('acq_verdict')!r}, attendu {verdict!r}")
        if hb.get("severity") != sev:
            faute(q, f"sévérité {hb.get('severity')}, attendu {sev}")
        if acquisition(evs):
            faute(q, "aveu d'acquisition émis alors que le moteur détecte encore")
        contient(q, hb.get("message"), *morceaux)

    def nouveau():
        bac = Bac(awk)
        bac.outil("cscli", FAUX_CSCLI)
        return bac

    # C1 — tout en liste blanche dès le premier passage (aucune ligne versée).
    bac = nouveau()
    try:
        res, evs = passage(bac, acq(100, 100, 0, 0, 100))
        refus_lb("crowdsec/tout/premier", evs, None, bac)
    finally:
        bac.nettoyer()
    # C2 — sur l'intervalle, après un passage sain.
    bac = nouveau()
    try:
        passage(bac, SAIN)
        avant = etat(bac)
        if avant is None:
            refus("aucun état posé après un passage sain : la comparaison ne prouverait rien")
        res, evs = passage(bac, acq(1100, 1000, 100, 7, 188))
        refus_lb("crowdsec/tout/intervalle", evs, avant, bac)
    finally:
        bac.nettoyer()
    # C2 bis — forme DISJOINTE (reads = parsed + unparsed + whitelisted) : 100 lues, 0 analysée hors liste
    # blanche, 100 en liste blanche -> refus aussi.
    bac = nouveau()
    try:
        passage(bac, SAIN)
        avant = etat(bac)
        res, evs = passage(bac, acq(1100, 900, 100, 7, 188))
        refus_lb("crowdsec/tout/disjointe", evs, avant, bac)
    finally:
        bac.nettoyer()
    # C3 — au seuil par défaut : 95 % en liste blanche, une ligne versée -> surtout_liste_blanche.
    for q, metrics2, env, verdict, sev, morceaux, avance in (
            ("crowdsec/surtout", acq(1100, 1000, 100, 8, 183), None, "surtout_liste_blanche", 2,
             ("ACQUISITION surtout_liste_blanche :", "95 %", "seuil 90 %", "mandataire"), True),
            ("crowdsec/seuil_regle", acq(1100, 1000, 100, 8, 183), {"PLUME_CROWDSEC_WHITELIST_SHARE_MAX": "96"},
             "lit", 0, ("liste blanche : 95 % des lignes analysées",), True),
            ("crowdsec/sous_le_seuil", acq(1100, 1000, 100, 10, 98), None, "lit", 0,
             ("liste blanche : 10 % des lignes analysées",), True),
            # au seuil EXACT (90 %) : surtout ; un point sous lui (89 %) : lit.
            ("crowdsec/au_seuil", acq(1100, 1000, 100, 8, 178), None, "surtout_liste_blanche", 2,
             ("90 %", "seuil 90 %"), True),
            ("crowdsec/sous_le_seuil_d_un_point", acq(1100, 1000, 100, 8, 177), None, "lit", 0,
             ("liste blanche : 89 % des lignes analysées",), True),
            # forme incluse, toutes les analysées en liste blanche mais une ligne versée : pas de refus, 100 %.
            ("crowdsec/versee_interdit_tout", acq(1100, 1000, 100, 8, 188), None, "surtout_liste_blanche", 2,
             ("100 %",), True),
            # forme DISJOINTE : 100 analysées hors liste blanche, aucune versée (trafic sans scénario qui le
            # retienne), 100 en liste blanche -> 50 %, lit — jamais un refus.
            ("crowdsec/disjointe_non_versee", acq(1200, 1000, 100, 7, 188), None, "lit", 0,
             ("liste blanche : 50 % des lignes analysées",), True)):
        bac = nouveau()
        try:
            passage(bac, SAIN, env)
            avant = etat(bac)
            res, evs = passage(bac, metrics2, env)
            sans_refus(q, evs, verdict, sev, *morceaux)
            if avance and etat(bac) == avant:
                faute(q, "l'état d'acquisition n'a pas avancé alors que le moteur lit")
        finally:
            bac.nettoyer()
    # C7 — seuil illisible : repli sur 90, dit.
    bac = nouveau()
    try:
        passage(bac, SAIN, {"PLUME_CROWDSEC_WHITELIST_SHARE_MAX": "beaucoup"})
        res, evs = passage(bac, acq(1100, 1000, 100, 8, 183), {"PLUME_CROWDSEC_WHITELIST_SHARE_MAX": "beaucoup"})
        sans_refus("crowdsec/seuil_illisible", evs, "surtout_liste_blanche", 2, "seuil 90 %")
        if len(aveux(evs, "crowdsec", "fallback", "unreadable-config")) != 1:
            faute("crowdsec/seuil_illisible", "seuil illisible non avoué (`fallback` / `unreadable-config`)")
    finally:
        bac.nettoyer()


# --- E. minio, F. dataaccess ----------------------------------------------------------------------
def banc_minio(awk):
    bac = Bac(awk)
    try:
        bac.outil("kubectl", '#!/bin/sh\ncase "$*" in\n  *"get pod"*) [ -f "$FAUX/pods_ko" ] && exit 1; '
                             'cat "$FAUX/pods" ;;\n  *) exit 1 ;;\nesac\n')
        for q, pods, ko, raison in (("minio/aucun_pod", "", False, "subsystem-absent"),
                                     ("minio/pod_arrete", "minio-0 Pending\n", False, "subsystem-absent"),
                                     ("minio/api_en_echec", "", True, "unreachable")):
            ecrire(os.path.join(bac.faux, "pods"), pods)
            ko_p = os.path.join(bac.faux, "pods_ko")
            if ko:
                ecrire(ko_p, "")
            elif os.path.exists(ko_p):
                os.remove(ko_p)
            res = bac.jouer("minio.sh")
            evs = evenements(q, res, "minio.sh")
            if len(aveux(evs, "minio", "unavailable", raison)) != 1:
                faute(q, f"cible absente non avouée par `{raison}` : {[e.get('message') for e in evs]}")
    finally:
        bac.nettoyer()


def banc_dataaccess(awk, nom_awk="awk"):
    bac = Bac(awk)
    try:
        log = os.path.join(bac.racine, "audit.log")
        ecrire(log, "")
        env = {"PLUME_AUDIT_LOG": log}
        cas = (("dataaccess/etc_seule", "-a always,exit -F dir=/etc -F perm=wa -F auid>=1000 -F auid!=-1 -F key=plume_etc\n",
                False, 1, ("PARTIEL", "chargées : plume_etc", "plume_data plume_creds"), True),
               ("dataaccess/donnees", "-a always,exit -F dir=/etc -F perm=wa -F key=plume_etc\n-w /srv/donnees -p wa -k plume_data\n",
                False, 0, ("actif", "plume_data plume_etc", "absentes : plume_creds"), False),
               ("dataaccess/creds_seule", "-a always,exit -F dir=/etc -F perm=wa -F key=plume_etc\n-w /srv/secrets -p r -k plume_creds\n",
                False, 0, ("actif", "plume_creds plume_etc", "absentes : plume_data"), False),
               # une clé dont le NOM commence par celui d'une clé de données n'est pas cette clé.
               ("dataaccess/cle_voisine", "-a always,exit -F dir=/etc -F perm=wa -F key=plume_etc\n-w /srv/vieux -p wa -k plume_data_archive\n",
                False, 1, ("PARTIEL", "chargées : plume_etc"), True),
               ("dataaccess/aucune", "", False, 1, ("PARTIEL", "chargées : aucune"), True),
               ("dataaccess/auditctl_en_echec", None, True, 1, ("couverture INCONNUE", "prouvées : aucune"), False),
               ("dataaccess/auditctl_absent", None, False, 1, ("couverture INCONNUE", "prouvées : aucune"), False))
        cles = []
        for q, regles, ko, sev, morceaux, aveu in cas:
            bac.retirer("auditctl")
            if regles is not None or ko:
                bac.outil("auditctl", "#!/bin/sh\nexit 1\n" if ko else "#!/bin/sh\ncat <<'X'\n" + regles + "X\n")
            res = bac.jouer("dataaccess.sh", env)
            evs = evenements(q, res, "dataaccess.sh")
            hb = un_battement(q, evs, "dataaccess")
            if hb:
                contient(q, hb.get("message"), *morceaux)
                if sev == 1 and "actif" in (hb.get("message") or ""):
                    faute(q, f"battement dit « actif » sans clé de données sue : {hb.get('message')!r}")
                if hb.get("severity") != sev:
                    faute(q, f"sévérité du battement {hb.get('severity')}, attendu {sev}")
                if (hb.get("fields") or {}).get("alive") != 1:
                    faute(q, "le battement ne porte plus `alive`")
            av = aveux(evs, "dataaccess", "unavailable", "missing-source")
            if aveu and len(av) != 1:
                faute(q, f"{len(av)} aveu(x) des clés de données absentes, attendu 1")
            if not aveu and av:
                faute(q, f"aveu émis alors qu'il n'y a rien à avouer : {av[0]['fields'].get('detail')}")
            if aveu and av:
                cles.append(av[0].get("dedup", "").rsplit("-", 1)[0])
                detail = (av[0].get("fields") or {}).get("detail") or ""
                # la lecture du journal est entière : l'aveu ne doit pas promettre une relecture qui n'aura pas lieu.
                if "N'AVANCE PAS" in detail or "sera relue" in detail:
                    faute(q, f"l'aveu dit que le marqueur n'avance pas, alors que le filigrane avance : {detail[:160]}")
                contient(q, detail, "le filigrane avance")
        if len(cles) != 3 or len(set(cles)) != 1:
            faute("dataaccess/cle", f"clé de dédoublonnage de l'aveu instable d'un cas à l'autre : {cles}")
    finally:
        bac.nettoyer()
    banc_dataaccess_preuves_du_journal(awk, nom_awk)


# P10.33-b — sous l'unité livrée, `auditctl -l` est refusé (CAP_AUDIT_CONTROL non accordée) : les clés sont
# PROUVÉES par le journal (SYSCALL `key=`, CONFIG_CHANGE `op=add_rule … res=1`, annulée par un `remove_rule`
# postérieur), sinon le battement avoue une couverture INCONNUE (sévérité 1, jamais « actif »).
def da_syscall(serie, cle, epoque=1758659000):
    return (f'type=SYSCALL msg=audit({epoque}.100:{serie}): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c '
            f'items=1 ppid=1 pid=2 auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" '
            f'key="{cle}"\n')


def da_config(serie, op, cle, res=1, enrichi=False):
    queue = '\x1dAUID="unset"' if enrichi else ""
    return (f'type=CONFIG_CHANGE msg=audit(1758650000.001:{serie}): auid=4294967295 ses=4294967295 subj=unconfined '
            f'op={op} key="{cle}" list=4 res={res}{queue}\n')


def da_demarrage(serie, noeud=""):
    return (f'{noeud}type=DAEMON_START msg=audit(1758655000.000:{serie}): op=start ver=3.1.2 format=enriched '
            f'kernel=6.8.0 auid=4294967295 pid=789 uid=0 ses=4294967295 subj=unconfined res=success'
            '\x1dAUID="unset" UID="root"\n')


def banc_dataaccess_preuves_du_journal(awk, nom_awk):
    LISTE_ETC = "-a always,exit -F dir=/etc -F perm=wa -F auid>=1000 -F auid!=-1 -F key=plume_etc\n"
    # (nom, auditctl : "echec" | "absent" | règles listées, journal courant, journal .1, sévérité, morceaux, absents)
    cas = (("vide", "echec", "", None, 1, ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("syscall_donnees", "echec", da_syscall(501, "plume_data"), None, 0,
            ("actif", "prouvées par le journal : plume_data", "non prouvées : plume_creds plume_etc"), ("INCONNUE",)),
           ("syscall_donnees_sans_auditctl", "absent", da_syscall(502, "plume_data"), None, 0,
            ("actif", "prouvées par le journal : plume_data"), ("INCONNUE",)),
           ("ajout_creds_enrichi", "echec", da_config(11, "add_rule", "plume_creds", enrichi=True), None, 0,
            ("actif", "prouvées par le journal : plume_creds"), ("INCONNUE",)),
           ("ajout_refuse", "echec", da_config(12, "add_rule", "plume_data", res=0), None, 1,
            ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("retiree_apres_acces", "echec", da_syscall(503, "plume_data") + da_config(13, "remove_rule", "plume_data"),
            None, 1, ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("retrait_refuse", "echec", da_syscall(504, "plume_data") + da_config(14, "remove_rule", "plume_data", res=0),
            None, 0, ("actif", "prouvées par le journal : plume_data"), ("INCONNUE",)),
           ("rechargee", "echec", da_config(15, "add_rule", "plume_data") + da_config(16, "remove_rule", "plume_data")
            + da_config(17, "add_rule", "plume_data"), None, 0, ("actif", "prouvées par le journal : plume_data"), ()),
           ("etc_seule", "echec", da_syscall(505, "plume_etc"), None, 1, ("couverture INCONNUE", "prouvées : plume_etc"), ()),
           ("cle_voisine", "echec", da_syscall(506, "plume_data_archive"), None, 1,
            ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("preuve_dans_le_journal_tourne", "echec", "", da_config(18, "add_rule", "plume_creds"), 0,
            ("actif", "prouvées par le journal : plume_creds"), ("INCONNUE",)),
           # P10.33-b — un DAEMON_START (auditd démarre : redémarrage, ou relance) efface les preuves qui le précèdent :
           # une règle chargée au boot précédent et non rechargée (augenrules arrêté à la première règle en échec)
           # ne doit pas se lire « actif ».
           ("redemarrage_sans_rechargement", "echec",
            da_config(21, "add_rule", "plume_data") + da_config(22, "add_rule", "plume_etc")
            + 'type=DAEMON_END msg=audit(1758654000.000:23): op=terminate auid=0 pid=1 subj=unconfined res=success\n'
            + da_demarrage(24) + da_config(25, "add_rule", "plume_etc"), None, 1,
            ("couverture INCONNUE", "prouvées : plume_etc"), ()),
           ("acces_avant_redemarrage", "echec", da_syscall(508, "plume_data") + da_demarrage(26), None, 1,
            ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("redemarrage_sous_prefixe_noeud", "echec", "node=hote " + da_syscall(509, "plume_creds")
            + da_demarrage(27, noeud="node=hote "), None, 1, ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("redemarrage_apres_le_tourne", "echec", da_demarrage(28), da_config(29, "add_rule", "plume_creds"), 1,
            ("couverture INCONNUE", "prouvées : aucune"), ()),
           ("rechargee_apres_redemarrage", "echec",
            da_syscall(510, "plume_creds") + da_demarrage(30) + da_config(31, "add_rule", "plume_data"), None, 0,
            ("actif", "prouvées par le journal : plume_data", "non prouvées : plume_creds plume_etc"), ("INCONNUE",)),
           # journal COURANT illisible (un répertoire à sa place) : `grep` échoue ; ce qu'il a lu du `.1` n'est pas une
           # preuve, la lecture est avouée en échec et la couverture dite INCONNUE.
           ("journal_courant_illisible", "echec", None, da_syscall(511, "plume_data"), 1,
            ("couverture INCONNUE", "prouvées : aucune"), ()),
           # auditctl lisible fait foi : le journal ne le contredit pas.
           ("auditctl_fait_foi", LISTE_ETC, da_syscall(507, "plume_data"), None, 1,
            ("PARTIEL", "chargées : plume_etc"), ("prouvées par le journal",)))
    for nom, auditctl, courant, tourne, sev, morceaux, absents in cas:
        q = f"dataaccess/{nom_awk}/journal/{nom}"
        bac = Bac(awk)
        try:
            log = os.path.join(bac.racine, "audit.log")
            if courant is None:
                os.mkdir(log)
            else:
                ecrire(log, courant)
            if tourne is not None:
                ecrire(log + ".1", tourne)
            if auditctl == "echec":
                bac.outil("auditctl", "#!/bin/sh\necho 'Error sending rule list data request (Operation not permitted)' >&2\nexit 1\n")
            elif auditctl != "absent":
                bac.outil("auditctl", "#!/bin/sh\ncat <<'X'\n" + auditctl + "X\n")
            res = bac.jouer("dataaccess.sh", {"PLUME_AUDIT_LOG": log})
            evs = evenements(q, res, "dataaccess.sh")
            hb = un_battement(q, evs, "dataaccess")
            if hb:
                msg = hb.get("message") or ""
                contient(q, msg, *morceaux)
                for m in absents:
                    if m in msg:
                        faute(q, f"{m!r} présent dans {msg!r}")
                if sev == 1 and "actif" in msg:
                    faute(q, f"battement dit « actif » sans clé de données prouvée : {msg!r}")
                if hb.get("severity") != sev:
                    faute(q, f"sévérité du battement {hb.get('severity')}, attendu {sev}")
            if courant is None:
                if not [a for a in aveux(evs, "dataaccess", "unavailable", "missing-source")
                        if "source_illisible" in ((a.get("fields") or {}).get("detail") or "")]:
                    faute(q, "journal courant illisible : la lecture en échec n'est pas avouée")
            elif nom != "auditctl_fait_foi" and aveux(evs, "dataaccess", "unavailable"):
                faute(q, "aveu `unavailable` émis alors que rien n'est constaté : l'alerte horaire tomberait sur un hôte calme")
        finally:
            bac.nettoyer()


# --- G. dataacl -----------------------------------------------------------------------------------
def banc_dataacl(awk, nom_awk):
    bac = Bac(awk)
    illisible = None
    try:
        arbre = os.path.join(bac.racine, "joyaux")
        os.makedirs(os.path.join(arbre, "sous"))
        ecrire(os.path.join(arbre, "sous", "prive"), "x")
        os.chmod(os.path.join(arbre, "sous", "prive"), 0o600)
        ecrire(os.path.join(arbre, "ouvert"), "x")
        os.chmod(os.path.join(arbre, "ouvert"), 0o666)
        illisible = os.path.join(bac.racine, "ferme")
        os.mkdir(illisible)
        os.chmod(illisible, 0)
        try:
            os.listdir(illisible)
            droits_tenus = False       # root : un mode 000 ne ferme rien, le cas illisible n'est pas jouable ici
        except PermissionError:
            droits_tenus = True
        absent = os.path.join(bac.racine, "absent")
        glob_vide = os.path.join(bac.racine, "*vault*")
        attendu_arbre = {arbre: "d", os.path.join(arbre, "sous"): "d", os.path.join(arbre, "ouvert"): "f"}
        cas = [  # (nom, PLUME_ACL_PATHS, raison de l'aveu « aucun chemin » ou None, illisibles avoués, chemins émis)
            ("pose_aucun_chemin", f"{absent} {glob_vide}", "missing-source", (), {}),
            ("un_present_un_absent", f"{absent} {arbre} {glob_vide}", None, (), attendu_arbre),
        ]
        if droits_tenus:
            cas += [("present_et_illisible", f"{arbre} {illisible}", None, (illisible,), dict(attendu_arbre, **{illisible: "d"})),
                    ("seul_illisible", f"{illisible} {absent}", None, (illisible,), {illisible: "d"})]
        else:
            print(f"{ETIQUETTE} : dataacl/{nom_awk} — droits non tenus (root ?) : cas « chemin illisible » non joué")
        for nom, chemins, raison_vide, illisibles, emis in cas:
            q = f"dataacl/{nom_awk}/{nom}"
            res = bac.jouer("dataacl.sh", {"PLUME_ACL_PATHS": chemins})
            evs = evenements(q, res, "dataacl.sh")
            tous = aveux(evs, "dataacl")
            vides = [e for e in tous if "aucun chemin de PLUME_ACL_PATHS" in ((e.get("fields") or {}).get("detail") or "")]
            fermes = [e for e in tous if "illisibles" in ((e.get("fields") or {}).get("detail") or "")]
            if len(tous) != len(vides) + len(fermes):
                faute(q, f"aveu inattendu : {[e['fields'].get('detail') for e in tous]}")
            if raison_vide:
                if len(vides) != 1:
                    faute(q, f"aucun chemin existant : {len(vides)} aveu(x) « aucun chemin », attendu 1 — {[e.get('message') for e in evs]}")
                else:
                    f = vides[0]["fields"]
                    if f.get("collect_status") != "unavailable" or f.get("reason") != raison_vide:
                        faute(q, f"aveu {f.get('collect_status')}/{f.get('reason')}, attendu unavailable/{raison_vide}")
                    contient(q, f.get("detail"), "PLUME_ACL_PATHS", "Aucune permission n'est cartographiee")
            elif vides:
                faute(q, f"aveu « aucun chemin » alors qu'un chemin existe : {vides[0]['fields'].get('detail')!r}")
            if illisibles:
                if len(fermes) != 1:
                    faute(q, f"chemin illisible : {len(fermes)} aveu(x), attendu 1")
                else:
                    f = fermes[0]["fields"]
                    if f.get("reason") != "missing-source" or f.get("collect_status") != "unavailable":
                        faute(q, f"aveu d'illisible {f.get('collect_status')}/{f.get('reason')}")
                    for p in illisibles:
                        contient(q, f.get("detail"), p)
                    if arbre in (f.get("detail") or "").replace(illisible, ""):
                        faute(q, f"un chemin lisible est dit illisible : {f.get('detail')!r}")
            elif fermes:
                faute(q, f"aveu d'illisible sans chemin illisible : {fermes[0]['fields'].get('detail')!r}")
            obtenus = {(e.get("fields") or {}).get("path"): (e.get("fields") or {}).get("type")
                       for e in evs if e.get("source") == "dataacl" and e.get("category") == "data"}
            if obtenus != emis:
                faute(q, f"carte émise {sorted(obtenus.items())}, attendu {sorted(emis.items())}")
    finally:
        if illisible and os.path.isdir(illisible):
            os.chmod(illisible, stat.S_IRWXU)
        bac.nettoyer()


# --- L'instrument ---------------------------------------------------------------------------------
def epreuve_de_l_instrument(awk):
    bac = Bac(awk, compter=True)
    try:
        env = {"PATH": bac.bin, "PLUME_GARDE_COMPTE": bac.compte}
        r = subprocess.run([os.path.join(bac.bin, "date"), "+%s"], env=env, capture_output=True, text=True)
        if r.stdout.strip() != str(HEURE):
            refus("le faux `date` ne rend pas l'heure fixée")
        subprocess.run([os.path.join(bac.bin, "cat"), "/dev/null"], env=env, check=False)
        if not os.path.exists(bac.compte) or open(bac.compte).read().count("\n") != 1:
            refus("l'enveloppe d'outil ne compte pas son lancement : le témoin structurel ne verrait rien")
        jouet = os.path.join(bac.racine, "jouet.sh")
        ecrire(jouet, 'n=0\nfor i in $N; do n=$((n + 1)); done\n')
        traces = []
        for n in ("1", "1 2 3 4 5 6 7 8"):
            r = subprocess.run([bac.sh, "-x", jouet], env=dict(env, N=n, PS4=MARQUE_DE_TRACE + " "),
                               capture_output=True, text=True)
            traces.append(r.stderr.count(MARQUE_DE_TRACE))
        if not traces[0] < traces[1]:
            refus(f"la trace `sh -x` d'une boucle ne grandit pas avec elle ({traces}) : le témoin structurel ne verrait rien")
    finally:
        bac.nettoyer()


def main():
    for f in ("auditd.sh", "web.sh", "crowdsec.sh", "minio.sh", "dataaccess.sh", "dataacl.sh", "lib.sh"):
        if not os.path.isfile(os.path.join(CAPTEURS, f)):
            refus(f"`collectors/{f}` introuvable")
    for o in ("sh", "jq", "date", "find"):
        if not shutil.which(o):
            refus(f"`{o}` absent : les capteurs ne peuvent pas être joués")
    for f in ("auditd.sh", "web.sh", "crowdsec.sh", "dataaccess.sh"):
        if not champs_declares(f):
            refus(f"en-tête `# plume-emits: fields=` illisible dans {f}")
    if not os.path.isfile(CORPUS) or not os.path.isfile(ATTENDU):
        refus("corpus différentiel d'auditd ou son attendu introuvable")
    with open(ATTENDU, encoding="utf-8") as fh:
        attendu = json.load(fh)
    if set(attendu) != set(REGLAGES) or any(f"auditd-{HEURE}.json" not in attendu[r] for r in REGLAGES):
        refus("l'attendu différentiel ne porte pas les quatre réglages et leur enveloppe d'événements")
    if len(lignes_du_corpus()) < 30:
        refus("corpus différentiel sous son plancher (30 enregistrements)")
    awks = []
    vus = set()
    for nom in AWK_EXERCES:
        p = shutil.which(nom)
        if p and os.path.realpath(p) not in vus:
            vus.add(os.path.realpath(p))
            awks.append((nom, p))
    if not awks:
        refus(f"aucun awk parmi {AWK_EXERCES}")
    epreuve_de_l_instrument(awks[0][1])
    for nom, p in awks:
        banc_auditd(p, nom, attendu)
        banc_web(p, nom)
    banc_crowdsec(awks[0][1])
    banc_minio(awks[0][1])
    for nom, p in awks:
        banc_dataaccess(p, nom)
        banc_dataacl(p, nom)
    if fautes:
        for x in fautes:
            print(f"::error::{x}")
        print(f"{ETIQUETTE} : {len(fautes)} faute(s)")
        return 1
    print(f"{ETIQUETTE} : tenu — awk joués : {', '.join(n for n, _ in awks)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
