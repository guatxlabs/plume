#!/usr/bin/env python3
"""Un capteur shell ne publie pas un nombre qu'il n'a pas pu lire — garde de SURFACE (`S36`).

CE QUE CETTE GARDE REND NON-ÉCRIVABLE
-------------------------------------
`S28`, `S32` et `S33` ont posé la forme côté démon puis sur une mesure d'hôte : une lecture qui
échoue ne produit AUCUNE valeur, et un AVEU nommant la cause l'accompagne. Les capteurs shell sont
l'une des surfaces où la donnée ENTRE, et la même figure y vivait, intacte : un tube dont le statut
est celui du dernier maillon, un `|| true` qui ramène l'échec au cas normal, un bloc `END` d'awk qui
imprime `0` sans une seule ligne d'entrée, une option non supportée dont l'erreur part sur la sortie
d'erreur pendant que la sortie standard reste vide. Le nombre publié est alors le plus CALME de sa
série — et il ARME des règles à seuil. Une règle dont l'entrée vaut 0 n'est pas en retard : elle est
STRUCTURELLEMENT INERTE, et rien ne le dit.

LA GARDE NE CORRIGE PAS UN CAPTEUR : ELLE TIENT LA SURFACE
----------------------------------------------------------
Sa portée est DÉCOUVERTE, jamais listée : tout `collectors/*.sh` dont le CODE EXÉCUTÉ publie une
AFFIRMATION que ses sources soient lisibles ou non — une enveloppe `kind:"metrics"`, ou un BATTEMENT
DE SANTÉ. La seconde forme a été ajoutée par `S36` parce que la première laissait dehors des capteurs
qui ne se taisaient pas mais AFFIRMAIENT : un battement partant à chaque passage avec « 0 ban actif »
ou « 0 scan vu » publie la valeur la plus calme de sa série sur une lecture qui a pu échouer. Un
capteur qui n'émet QUE ce qu'il a vu reste hors portée, et c'est délibéré : ses deux témoins seraient
identiques, et lui réclamer un aveu reviendrait à lui faire crier à chaque période calme.
Un capteur ajouté demain est donc contrôlé d'office, et retirer un capteur de la portée demande de
cesser d'affirmer — pas d'éditer une liste.
Le code COMMENTÉ est exclu par une machine à états sur les guillemets : une publication qui
n'existe que dans un commentaire n'en est pas une, et un témoin le vérifie.

DEUX PARTS, ET LA SECONDE EST CELLE QUI MESURE
----------------------------------------------
(A) STATIQUE — un capteur qui publie des nombres doit AVOIR un chemin vers le canal d'aveu
    (`plume_mesures_avouer`, `plume_lecture_partielle`, `plume_lecture_echouee` : les trois passent
    par `plume_report_availability`, sur lequel une règle livrée alerte déjà). Sans ce chemin, il ne
    PEUT rien faire d'autre que publier une valeur rassurante. C'est une condition nécessaire, pas
    suffisante — et c'est pourquoi la part (B) existe.

(B) DYNAMIQUE — MUTATION DANS LES DEUX SENS, UNE COMMANDE À LA FOIS. Le capteur est exécuté TEL
    QU'IL EST LIVRÉ contre un PATH fabriqué où chacune de ses commandes externes est un stub :
      TÉMOIN (1) tous les stubs rendent 0 avec une sortie VIDE   -> une source LUE, réellement vide.
      TÉMOIN (2) un seul stub rend 1, les autres restent à 0      -> cette lecture-là a ÉCHOUÉ.
    Entre les deux, un seul bit change. Ce que la garde exige est que la SORTIE PUBLIÉE change avec
    lui : si le capteur publie exactement les mêmes séries dans les deux cas, il a converti un échec
    en valeur normale, et c'est refusé. Les clés ne sont pas énumérées : celles du témoin (2) sont
    DÉCOUVERTES dans la sortie du témoin (1).

    Le témoin (1) est le cœur, et sans lui la garde ne prouverait rien : un capteur qui n'émettrait
    PLUS JAMAIS de nombre passerait le témoin (2) sans effort, et ferait disparaître le cas nominal —
    un pare-feu réellement sans blocage, un cluster réellement au repos, un ruleset réellement vide.

LES STUBS : LE DÉFAUT EST DE STUBER, L'EXCEPTION EST OUTILLÉE
-------------------------------------------------------------
Les commandes à stuber sont EXTRAITES du capteur (tout mot en position de commande qui n'est ni un
mot-clé du shell, ni une fonction définie dans le fichier ou dans `lib.sh`). N'en sont retirés que
les OUTILS DU HARNAIS — les utilitaires de texte et de fichiers sans lesquels le capteur ne peut pas
tourner du tout. Cette liste-là n'énumère aucune mesure et aucun capteur : elle décrit ce que la
garde doit laisser réel pour pouvoir exécuter quoi que ce soit. Le sens de l'exception est celui qui
protège — une SOURCE nouvelle est stubée d'office, parce qu'elle n'y figure pas.

CE QUE CETTE GARDE NE PROUVE PAS, ET C'EST DIT
----------------------------------------------
  * Un capteur peut lire une source par un chemin absolu que le PATH ne gouverne pas (`/proc`, un
    fichier d'état) ; la mutation ne l'atteint pas. Le verdict porte sur la DIFFÉRENCE entre deux
    exécutions faites sur la MÊME machine, ce qui neutralise la part que la machine apporte, mais ne
    la remplace pas : `check_host_measures_are_honest.py` couvre `/proc` pour le capteur qui le lit.
  * Les utilitaires du harnais restent réels ; un capteur qui LIRAIT par l'un d'eux (`cat` d'un
    fichier d'état, `tail` d'un journal) n'est pas muté sur cette lecture-là.
  * La part (A) vérifie qu'un chemin d'aveu EXISTE, jamais qu'il est emprunté au bon endroit.
  * Un capteur dont le témoin (1) ne publie AUCUN nombre est déclaré NON EXERÇABLE et compté comme
    tel : ce n'est pas un vert. Sous deux capteurs exerçables, la garde ÉCHOUE au lieu de conclure —
    une garde qui ne trouve rien parce que son harnais est cassé rendrait vert en étant aveugle.
  * Un stub à sortie VIDE n'est pas une lecture nominale pour toute commande : pour celles dont une
    sortie vide EST déjà un échec, le capteur avoue dès le témoin (1) et la mutation ne change rien.
    Ce cas est déclaré INCONCLUANT — jamais vert, et il ne compte pas pour le plancher.

L'INSTRUMENT EST VALIDÉ AVANT D'ÊTRE CRU : la part (A) tourne d'abord sur trois fragments fabriqués
— un qui DOIT être refusé, deux qui DOIVENT passer, dont un où la publication n'existe que dans un
commentaire. Si l'un des trois ne rend pas le verdict attendu, la garde s'arrête là.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAPTEURS = os.path.join(RACINE, "collectors")
LIB = os.path.join(CAPTEURS, "lib.sh")

# CE QUI MET UN CAPTEUR DANS LA PORTÉE : il PUBLIE UNE AFFIRMATION même quand ses sources n'ont rien
# rendu. Deux formes, et une seule raison commune — dans les deux cas le capteur dit quelque chose
# qu'un lecteur en aval croira, alors qu'il n'a peut-être rien mesuré ; c'est ce qui rend la
# différence entre les deux témoins MESURABLE. Un capteur dont le silence est légitime (il n'émet que
# lorsqu'il a vu quelque chose) n'est pas dans la portée : ses deux témoins seraient identiques, et
# exiger un aveu de lui reviendrait à lui demander de crier à chaque période calme.
#   (a) une enveloppe de NOMBRES — la série publiée est lue par des règles à seuil ;
#   (b) un BATTEMENT DE SANTÉ — il part à chaque passage par construction (son silence lève une
#       alerte MUET), et il porte souvent un compteur (« 0 ban actif », « 0 scan vu ») qui est
#       exactement la valeur la plus calme de sa série.
PUBLIE_DES_NOMBRES = re.compile(r'kind"\s*:\s*"metrics"')
PUBLIE_UN_BATTEMENT = re.compile(r'(?<![A-Za-z0-9_])heartbeat\s+[A-Za-z0-9_"$-]')

# Les trois portes du canal d'aveu (toutes trois passent par `plume_report_availability`).
PORTES_D_AVEU = ("plume_mesures_avouer", "plume_lecture_partielle", "plume_lecture_echouee")

# Mots-clés et primitives du shell : jamais des commandes externes.
MOTS_DU_SHELL = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "select", "time", "coproc", "return", "exit", "break", "continue",
    "set", "unset", "export", "readonly", "local", "shift", "eval", "exec", "trap", "wait",
    "read", "printf", "echo", "test", "true", "false", "cd", "pwd", "umask", "ulimit", "alias",
    "command", "type", "hash", "getopts", "source", ".", ":", "[", "[[", "{", "}", "(", ")",
}

# OUTILS DU HARNAIS — laissés RÉELS pour que le capteur puisse tourner. Ce n'est pas une liste de
# mesures ni de capteurs : c'est l'outillage de texte et de fichiers du shell. Le défaut reste de
# stuber ; ce qui n'est pas ici est une SOURCE, et une source nouvelle est donc mutée d'office.
OUTILS_DU_HARNAIS = {
    "sh", "bash", "env", "awk", "gawk", "mawk", "sed", "grep", "egrep", "cut", "tr", "sort",
    "uniq", "head", "tail", "wc", "cat", "comm", "paste", "join", "rev", "nl", "expr", "seq",
    "basename", "dirname", "readlink", "realpath", "mktemp", "rm", "mv", "cp", "ln", "mkdir",
    "rmdir", "chmod", "chown", "touch", "sync", "sleep", "date", "hostname", "id", "stat",
    "cksum", "sha256sum", "sha1sum", "md5sum", "base64", "xargs", "tee", "getent", "logger",
}

MIN_CAPTEURS_EXERCABLES = 2


def echec(msg):
    print(f"::error::{msg}")
    sys.exit(1)


# --------------------------------------------------------------------------------------------------
# CODE EXÉCUTÉ : commentaires et heredocs cités retirés (machine à états sur les guillemets).
# --------------------------------------------------------------------------------------------------
def code_execute(texte):
    lignes, heredoc = [], None
    for ligne in texte.splitlines():
        if heredoc is not None:
            if ligne.strip() == heredoc:
                heredoc = None
            continue
        m = re.search(r"<<-?\s*'([A-Za-z_][A-Za-z0-9_]*)'", ligne)
        if m:
            heredoc = m.group(1)
        sortie, guillemet, i, n = [], None, 0, len(ligne)
        while i < n:
            c = ligne[i]
            if guillemet:
                sortie.append(c)
                if c == guillemet:
                    guillemet = None
                elif c == "\\" and guillemet == '"' and i + 1 < n:
                    sortie.append(ligne[i + 1])
                    i += 1
            elif c in "'\"":
                guillemet = c
                sortie.append(c)
            elif c == "#" and (i == 0 or ligne[i - 1] in " \t;&|("):
                break
            else:
                sortie.append(c)
            i += 1
        lignes.append("".join(sortie))
    return "\n".join(lignes)


def fonctions_definies(texte):
    return set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)", texte, re.M))


def sans_litteraux(code):
    """Neutralise le CONTENU des chaînes citées. Un programme awk est un ARGUMENT, pas du shell : ses
    `|`, ses accolades et ses mots ne sont pas des positions de commande. Sans cette étape, un motif
    de regex passait pour une commande externe — et une garde qui stube un mot d'une regex ne mesure
    plus ce qu'elle prétend."""
    sortie, guillemet = [], None
    for c in code:
        if guillemet:
            sortie.append("\n" if c == "\n" else ("_" if c != guillemet else c))
            if c == guillemet:
                guillemet = None
        elif c in "'\"":
            guillemet = c
            sortie.append(c)
        else:
            sortie.append(c)
    return "".join(sortie)


def commandes_externes(code, connues):
    """Mots en POSITION DE COMMANDE qui ne sont ni du shell, ni une fonction, ni un outil du harnais."""
    code = sans_litteraux(code)
    code = re.sub(r"\$\(\(.*?\)\)", "__", code, flags=re.S)   # `$(( … ))` : de l'arithmétique, pas des commandes
    trouvees = set()
    for m in re.finditer(r"command\s+-v\s+([A-Za-z][A-Za-z0-9._+-]*)", code):
        trouvees.add(m.group(1))
    # une position de commande s'ouvre en début de ligne ou après un séparateur de commande
    for segment in re.split(r"(?:^|[\n;&|(]|\|\||&&|\$\(|`)", code):
        mots = segment.strip().split()
        i = 0
        while i < len(mots):
            mot = mots[i]
            if mot in ("!", "then", "do", "else", "elif", "time", "command", "env"):
                i += 1
                continue
            break
        if i >= len(mots):
            continue
        mot = mots[i]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9._+-]*", mot or ""):
            trouvees.add(mot)
    return sorted(
        c for c in trouvees
        if c not in MOTS_DU_SHELL and c not in OUTILS_DU_HARNAIS and c not in connues
    )


# --------------------------------------------------------------------------------------------------
# PART (A) — un capteur qui publie des nombres doit avoir un chemin vers le canal d'aveu.
# --------------------------------------------------------------------------------------------------
def verdict_statique(texte):
    """Rend (dans_la_portee, a_un_chemin_d_aveu) pour le TEXTE d'un capteur."""
    code = code_execute(texte)
    dans_la_portee = bool(PUBLIE_DES_NOMBRES.search(code)) or bool(PUBLIE_UN_BATTEMENT.search(code))
    return dans_la_portee, any(p in code for p in PORTES_D_AVEU)


def valider_l_instrument():
    """Trois fragments fabriqués : un refusé, deux acceptés — dont un où tout est en commentaire."""
    coupable = 'spool_write "x-$ts.json" "$(printf \'{"kind":"metrics","data":{}}\')"\n'
    innocent = coupable + "plume_mesures_avouer x\n"
    commente = "# " + coupable
    battement = 'spool_write "x-$ts.json" "$(emit_event "$(heartbeat x \'vivant\' \'{}\')")"\n'
    hors_portee = 'events="$events,{\"ts\":$ts}"\nspool_write "x-$ts.json" "$(emit_event "$events")"\n'
    for nom, fragment, portee_attendue, aveu_attendu in (
        ("témoin POSITIF (publie sans aveu)", coupable, True, False),
        ("témoin NÉGATIF (publie et avoue)", innocent, True, True),
        ("témoin NÉGATIF (publication COMMENTÉE)", commente, False, False),
        ("témoin POSITIF (battement de santé sans aveu)", battement, True, False),
        ("témoin NÉGATIF (n'émet que ce qu'il a vu)", hors_portee, False, False),
    ):
        portee, aveu = verdict_statique(fragment)
        if portee != portee_attendue or aveu != aveu_attendu:
            echec(
                f"instrument NON VALIDE sur le {nom} : portée={portee} (attendu {portee_attendue}), "
                f"chemin d'aveu={aveu} (attendu {aveu_attendu}). La garde s'arrête plutôt que de "
                "rendre un verdict avec un instrument qu'elle n'a pas contrôlé."
            )

    # L'EXTRACTEUR DE COMMANDES EST UN INSTRUMENT AUSSI, et le sien se trompe dans les deux sens :
    # rater une source, c'est ne rien muter ; prendre un mot d'un programme awk pour une commande,
    # c'est stuber du vide et croire avoir mesuré. Un témoin par sens.
    fragment = "sonde -k --depuis \"@$last\" | awk '/Erreur|Panne/ {print $1}' > \"$f\"\n"
    extraites = commandes_externes(code_execute(fragment), set())
    if "sonde" not in extraites:
        echec("instrument NON VALIDE : la commande en tête de tube n'est pas extraite -> rien ne serait muté")
    if "Erreur" in extraites or "Panne" in extraites:
        echec("instrument NON VALIDE : un mot d'un programme awk est pris pour une commande externe")
    if "reste" in commandes_externes(code_execute("d=$(( (reste - 1) / 2 ))\n"), set()):
        echec("instrument NON VALIDE : un terme d'expansion arithmétique est pris pour une commande")


# --------------------------------------------------------------------------------------------------
# PART (B) — mutation, une commande à la fois.
# --------------------------------------------------------------------------------------------------
def poser_les_stubs(repertoire, commandes, en_echec, trace):
    """Chaque stub TRACE son appel. L'extraction de commandes est un instrument faillible — un mot
    d'une expansion arithmétique ou d'une branche jamais prise s'y glisse. Muter une commande que le
    capteur n'APPELLE PAS produirait deux exécutions identiques et un faux rouge. La trace remplace
    donc l'hypothèse par une MESURE : seules les commandes réellement invoquées au témoin (1) sont
    mutées, et un capteur qui n'en invoque aucune est déclaré NON EXERÇABLE plutôt que vert."""
    for c in commandes:
        chemin = os.path.join(repertoire, c)
        code = 1 if c == en_echec else 0
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\nprintf \'%s\\n\' {c} >> "{trace}" 2>/dev/null\nexit {code}\n')
        os.chmod(chemin, 0o755)


def executer(capteur, commandes, en_echec):
    """Exécute le capteur et rend (rc, métriques publiées, textes des aveux, commandes appelées)."""
    with tempfile.TemporaryDirectory() as base:
        binz = os.path.join(base, "bin")
        spool = os.path.join(base, "spool")
        etat = os.path.join(base, "state")
        for d in (binz, spool, etat):
            os.makedirs(d)
        trace = os.path.join(base, "appels")
        poser_les_stubs(binz, commandes, en_echec, trace)
        env = dict(
            os.environ,
            PATH=binz + os.pathsep + os.environ.get("PATH", ""),
            PLUME_LIB=LIB,
            PLUME_SPOOL=spool,
            PLUME_STATE=etat,
        )
        r = subprocess.run(["sh", capteur], env=env, capture_output=True, text=True, timeout=120)
        mesures, battements, aveux = set(), set(), []
        for nom in sorted(os.listdir(spool)):
            # LES TEMPORAIRES NE SONT PAS DES PUBLICATIONS. `spool_publish_file` compose l'enveloppe
            # dans un `.nom.XXXXXX` puis la RENOMME ; `ship.sh` ne parcourt que les noms visibles.
            # Lire un temporaire ferait échouer la garde sur un fichier que personne n'expédie.
            if nom.startswith("."):
                continue
            chemin = os.path.join(spool, nom)
            try:
                import json
                doc = json.load(open(chemin, encoding="utf-8"))
            except Exception as e:  # noqa: BLE001 — un spool illisible est un échec de garde
                echec(f"{os.path.basename(capteur)} a publié une enveloppe illisible `{nom}` ({e})")
            for m in doc.get("data", {}).get("metrics", []):
                mesures.add(m["name"])
            for ev in doc.get("events", []):
                if ev.get("fields", {}).get("type") != "collector-availability":
                    # IDENTITÉ DE CE QUI EST AFFIRMÉ, pas son contenu : un battement porte un
                    # horodatage et un compteur qui bougent d'une exécution à l'autre, et comparer
                    # des contenus ferait conclure « ça a changé » à chaque fois.
                    battements.add("%s/%s" % (ev.get("source", "?"), ev.get("category", "?")))
                if ev.get("fields", {}).get("type") == "collector-availability":
                    # Le chemin du répertoire fabriqué change à chaque exécution et apparaît dans le
                    # texte des aveux ; sans le neutraliser, deux aveux IDENTIQUES seraient comparés
                    # comme différents et la garde conclurait un changement là où rien n'a bougé.
                    texte = (ev["fields"].get("detail", "") + " " + ev.get("message", ""))
                    aveux.append(texte.replace(base, "<harnais>"))
        appelees = set()
        if os.path.exists(trace):
            appelees = {l.strip() for l in open(trace, encoding="utf-8") if l.strip()}
        return r, mesures, aveux, appelees, battements


def main():
    valider_l_instrument()

    if shutil.which("sh") is None or not os.path.exists(LIB):
        echec("ni `sh` ni `lib.sh` : la garde ne peut pas rendre de verdict (et n'en rendra pas un faux)")

    fonctions_de_lib = fonctions_definies(open(LIB, encoding="utf-8").read())

    portee, sans_aveu = [], []
    for nom in sorted(os.listdir(CAPTEURS)):
        if not nom.endswith(".sh") or nom == "lib.sh":
            continue
        chemin = os.path.join(CAPTEURS, nom)
        texte = open(chemin, encoding="utf-8").read()
        dans_portee, a_un_aveu = verdict_statique(texte)
        if not dans_portee:
            continue
        portee.append((nom, chemin, texte))
        if not a_un_aveu:
            sans_aveu.append(nom)

    if not portee:
        echec(
            "AUCUN capteur ne publie d'enveloppe `kind:\"metrics\"` ni de battement de santé — la "
            "portée est vide, donc l'instrument est cassé : la garde refuse de conclure au lieu de "
            "rendre vert."
        )
    if sans_aveu:
        echec(
            f"ces capteurs AFFIRMENT (nombres ou battement) sans aucun chemin vers le canal d'aveu {PORTES_D_AVEU} : "
            f"{sans_aveu}. Un capteur qui ne peut pas dire qu'une mesure manque ne peut publier qu'une "
            "valeur rassurante à sa place."
        )

    exercables, rapport = 0, []
    for nom, chemin, texte in portee:
        code = code_execute(texte)
        connues = fonctions_definies(texte) | fonctions_de_lib
        commandes = commandes_externes(code, connues)
        if not commandes:
            rapport.append(f"{nom} : aucune commande externe extraite -> NON EXERÇABLE")
            continue

        r1, m1, a1, appelees, b1 = executer(chemin, commandes, en_echec=None)
        if r1.returncode != 0:
            echec(f"{nom} (témoin 1, sources lues et vides) : sortie {r1.returncode} — {r1.stderr.strip()[:300]}")
        if not m1 and not b1:
            rapport.append(f"{nom} : témoin (1) ne publie RIEN -> NON EXERÇABLE ({commandes})")
            continue
        incoherents = sorted(k for k in m1 if any(k in t for t in a1))
        if incoherents:
            echec(
                f"{nom} (témoin 1) : ces séries sont PUBLIÉES et pourtant nommées dans un aveu — "
                f"{incoherents}. L'aveu et l'enveloppe se contredisent."
            )

        if not appelees:
            rapport.append(f"{nom} : aucune commande externe RÉELLEMENT appelée -> NON EXERÇABLE")
            continue

        concluantes = 0
        for c in sorted(appelees):
            r2, m2, a2, _, b2 = executer(chemin, commandes, en_echec=c)
            if r2.returncode != 0:
                echec(f"{nom} (témoin 2, `{c}` en échec) : sortie {r2.returncode} — {r2.stderr.strip()[:300]}")
            # CE QUE LA MUTATION DOIT CHANGER : ou bien une série publiée DISPARAÎT, ou bien un AVEU
            # apparaît. Exiger la seule disparition serait faux pour un capteur dont la publication
            # est un BATTEMENT : il doit continuer de battre (son silence lève une alerte MUET) et
            # c'est l'aveu qui porte la différence. Exiger le seul aveu serait faux pour une série de
            # nombres : un aveu laisserait le nombre en place, et c'est le nombre que la règle lit.
            # « Un aveu apparaît » se mesure sur le TEXTE, pas sur le compte : un capteur qui avoue
            # déjà autre chose (une source hors mutation) doit quand même NOMMER la lecture qui vient
            # d'échouer, sans quoi deux causes distinctes se diraient du même mot.
            if m2 == m1 and b2 == b1 and sorted(a2) == sorted(a1):
                # UN STUB À SORTIE VIDE N'EST PAS UNE LECTURE NOMINALE POUR TOUTE COMMANDE. Pour
                # celles dont la sortie vide EST déjà un échec (une occupation de disque, un état),
                # le capteur avoue DÉJÀ au témoin (1) : la mutation ne change alors rien parce qu'il
                # n'y avait rien de nominal à casser, et conclure « conversion » serait un faux
                # rouge. Ce cas est déclaré INCONCLUANT, compté comme tel, et il ne rend pas le
                # capteur exerçable — il ne peut donc pas servir à passer le plancher.
                if a1 and a2 == a1:
                    rapport.append(
                        f"{nom} : `{c}` -> mutation INCONCLUANTE (le témoin (1) avouait déjà ; "
                        "une sortie vide n'est pas une lecture nominale pour cette commande)"
                    )
                    continue
                echec(
                    f"{nom} : `{c}` en ÉCHEC publie exactement les mêmes séries que `{c}` LU et vide "
                    f"({sorted(m1)}). L'échec est converti en valeur normale — une règle à seuil qui "
                    "consomme ces séries est INERTE sans que rien ne le dise. Un aveu ne suffirait "
                    "pas : il laisserait le nombre en place, et c'est le nombre que la règle lit."
                )
            concluantes += 1
            if not a2:
                echec(
                    f"{nom} : `{c}` en échec fait disparaître {sorted((m1 - m2) | (b1 - b2))} SANS aucun "
                    "aveu `collector-availability`. L'absence seule ne distingue pas « la lecture a "
                    "échoué » d'un relevé manqué."
                )
            texte_aveu = " ".join(a2)
            if m2:
                muettes = sorted(k for k in (m1 - m2) if k not in texte_aveu)
                if muettes:
                    echec(
                        f"{nom} : `{c}` en échec fait disparaître {muettes} sans que l'aveu les NOMME — "
                        "une série peut donc disparaître sans un mot."
                    )
                menteuses = sorted(k for k in m2 if k in texte_aveu)
                if menteuses:
                    echec(
                        f"{nom} : `{c}` en échec avoue {menteuses} alors que ces séries sont PUBLIÉES."
                    )
            perdu = sorted((m1 - m2) | (b1 - b2))
            rapport.append(f"{nom} : `{c}` en échec -> {perdu or 'même publication, mais AVOUÉE'}, avoué")

        if concluantes:
            exercables += 1
        else:
            rapport.append(f"{nom} : AUCUNE mutation concluante -> NON EXERÇABLE")

    if exercables < MIN_CAPTEURS_EXERCABLES:
        echec(
            f"seulement {exercables} capteur(s) exerçable(s) sur {len(portee)} dans la portée — sous le "
            f"plancher de {MIN_CAPTEURS_EXERCABLES}, c'est le harnais qui est cassé, pas la surface ; "
            "la garde refuse de conclure. " + " | ".join(rapport)
        )

    print(f"OK — {len(portee)} capteur(s) qui AFFIRMENT (nombres ou battement), {exercables} exercé(s) "
          "de bout en bout :")
    for ligne in rapport:
        print(f"   {ligne}")


if __name__ == "__main__":
    main()
