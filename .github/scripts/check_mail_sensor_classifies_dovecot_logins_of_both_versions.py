#!/usr/bin/env python3
"""Le capteur mail classe les connexions Dovecot 2.3 ET 2.4, lit l'adresse source ENTIÈRE, et ne prend jamais un texte du client pour un verdict — garde de CI (`P10.22-j`, `P10.22-s`, `P10.22-v`).

LES DÉFAUTS QUE CETTE GARDE REND NON-ÉCRIVABLES
-----------------------------------------------
`P10.22-j` — mesuré le 2026-09-23 sur un pod d'essai docker-mailserver 16.0.1 (Dovecot 2.4.1) : une
connexion réussie s'y journalise `imap-login: Logged in: user=<…>`, là où la production (2.3.19.1)
écrit `imap-login: Login: user=<…>`. `collectors/mail.sh` ne reconnaissait que `Login:` : après la
montée du serveur mail, plus AUCUNE connexion réussie n'aurait été émise.
`P10.22-s` — mesuré le 2026-09-23 sur le capteur : `rip=2001:db8::5` rendait `src_ip="2001"` ;
`rip=::ffff:192.0.2.40` rendait une adresse vide et l'échec était jeté sans un mot ; un échec SASL
Postfix venu d'une adresse IPv6 était jeté ; un rejet venu d'une adresse IPv6 portait l'adresse que
le CLIENT avait écrite dans son `helo=<[…]>`.
`P10.22-v` — mesuré le même jour : le bras d'échec cherchait `auth failed`, `authentication failed`
et `Aborted login` PARTOUT dans la ligne. Postfix recopie dans son journal le HELO, l'expéditeur,
une commande non SMTP, un texte de pré-salutation — des lignes que n'importe quel client produit
sans s'authentifier : chacune devenait un échec d'authentification, à l'adresse et au compte que le
client écrivait (`rip=`, `user=<…>` étaient lus partout eux aussi). L'étiquette ` dovecot: ` était
cherchée partout : un client qui l'écrivait fabriquait une connexion RÉUSSIE. L'échec SASL de notre
propre relais sortant était imputé à l'adresse du relais.

CE QUE LA GARDE FAIT
--------------------
Elle lit deux corpus — `collectors/mail-connexions-dovecot.corpus` (connexions Dovecot 2.3 et 2.4) et
`collectors/mail-adresses-et-texte-du-client.corpus` (adresses, lignes Postfix, textes du client) —
où chaque ligne porte son verdict attendu et la PROVENANCE de sa forme, écrit ces lignes dans un
journal fabriqué, exécute le capteur TEL QU'IL EST LIVRÉ en mode fichier (`PLUME_MAIL_SRC=file`)
dans un bac — spool, état et journal à lui — puis relit l'enveloppe publiée et juge CHAQUE ligne :
  * `succes` / `echec` / `rejet` / `postscreen` -> exactement un événement de la catégorie et de
    l'action attendues, avec le `user`, le `src_ip` et le `service` attendus ;
  * `aucun`  -> aucun événement ;
  * et aucun événement dont le message n'est pas une ligne d'un corpus (rien d'inventé).
Elle exécute aussi, isolées du capteur livré, ses fonctions d'adresse (`est_ipv4`, `est_ipv6`,
`adresse`) sur une table de valeurs valides et invalides.
Tout est joué sous CHAQUE implémentation d'awk présente parmi `gawk` et `mawk` (l'hôte Debian/Ubuntu
livre `mawk` par défaut ; mawk 1.3.4 20200120, celui de Debian 12 et d'Ubuntu 22.04, ne connaît pas
les intervalles `{n,m}` et ne double pas un antislash écrit "\\\\") : la classification est un
programme awk, et un motif qu'une implémentation lit autrement est un capteur qui ne classe pas
pareil selon l'hôte.

LES CORPUS SE VALIDENT AVANT DE SERVIR
--------------------------------------
Un corpus qui perd sa matière rend un vert vide. Avant toute exécution : cinq colonnes, un verdict
et une provenance des vocabulaires fermés, un horodatage ISO et une étiquette syslog reconnue en
tête, une provenance de la famille de l'étiquette ; aucune ligne « Login aborted » déclarée
`succes`, aucune ligne `client-postfix` déclarée `succes` ou `echec` (un corpus ne peut pas
légitimer le défaut qu'il garde) ; le `user` attendu est celui du message Dovecot, et `-` sur toute
ligne Postfix ; le `src_ip` attendu est une adresse sous sa forme rendue (jamais mappée) et figure
dans la ligne là où le serveur l'écrit (`rip=` Dovecot, `[…]` Postfix) ; toute adresse, IPv4 ou
IPv6, est de documentation (RFC 5737, RFC 3849) ou de bouclage ; tout utilisateur Dovecot est vide,
sous `example.test`, ou sur une ligne fabriquée. Chaque corpus a son PLANCHER, écrit exigence par
exigence ci-dessous. Cette validation est elle-même éprouvée sur des lignes FABRIQUÉES : une ligne
conforme passe, et six écarts sont CHACUN refusés.

LE JUGE SE VALIDE AUSSI
-----------------------
Avant de juger le capteur, le juge est éprouvé sur des événements FABRIQUÉS : le résultat exact ne
doit rien accuser ; un succès manquant, un succès rendu en échec, un rejet rendu en échec, un
événement pour une ligne `aucun`, un `user` faux, un `src_ip` faux, un `service` faux et un
événement inventé doivent CHACUN être accusés.

CE QUE LA GARDE NE TIENT PAS, DIT FRANCHEMENT
---------------------------------------------
Elle éprouve la CLASSIFICATION du capteur livré, pas ce qui tourne sur l'hôte : un capteur corrigé
ici et jamais installé ne classe rien (famille de `P10.22-i`). Les formes `sources-*` sont dérivées
des sources, pas relevées ; seules les lignes `mesuree-*` l'ont été, et aucune ligne Postfix ne
l'est. Les bras « postscreen » et « rejet » lisent encore la ligne entière : un texte du client peut
y choisir entre ces deux catégories (toutes deux `blocked`, à l'adresse du client). Qu'une première
adresse entre crochets invalide ne fasse JAMAIS chercher plus loin n'a pas de témoin : aucune forme
réelle de Postfix ne l'écrit. Les unités awk des capteurs échappent au recensement des définitions
d'adresse de `P4.7-j`.
Sortie : 0 tenu · 1 défaut · 2 rien n'a été mesuré (capteur, bibliothèque ou corpus absent, corpus
invalide ou sous son plancher, juge ou validation non discriminants, aucun awk, capteur en échec,
fonction d'adresse introuvable, spool illisible).
"""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CAPTEUR = os.path.join(RACINE, "collectors", "mail.sh")
LIB = os.path.join(RACINE, "collectors", "lib.sh")
CORPUS_DOVECOT = os.path.join(RACINE, "collectors", "mail-connexions-dovecot.corpus")
CORPUS_CLIENT = os.path.join(RACINE, "collectors", "mail-adresses-et-texte-du-client.corpus")
ETIQUETTE = "P10.22-j/s/v"

CLASSE_DU_VERDICT = {"succes": ("auth", "success"), "echec": ("auth", "failure"),
                     "rejet": ("reject", "blocked"), "postscreen": ("postscreen", "blocked"),
                     "aucun": None}
# Chaque corpus : ses verdicts, et pour chaque provenance la famille d'étiquette qu'elle exige.
SPEC_DOVECOT = dict(
    nom="mail-connexions-dovecot.corpus",
    verdicts=("succes", "echec", "aucun"),
    provenances={p: "dovecot" for p in ("mesuree-2.4.1", "sources-2.4.1", "fabriquee-2.4",
                                         "mesuree-2.3.19.1", "enonce-2.3", "sources-2.3.19.1", "fabriquee-2.3")},
)
SPEC_CLIENT = dict(
    nom="mail-adresses-et-texte-du-client.corpus",
    verdicts=tuple(CLASSE_DU_VERDICT),
    provenances={"sources-2.3.19.1": "dovecot", "sources-2.4.1": "dovecot", "fabriquee-2.4": "dovecot",
                 "enonce-P10.22-s": "dovecot", "sources-postfix": "postfix",
                 "sources-postfix-avant-3.9": "postfix", "client-postfix": "postfix"},
)
SERVICES_DE_CONNEXION = ("imap", "pop3", "submission", "managesieve")
AWK_EXERCES = ("gawk", "mawk")
PLAGES_DE_DOCUMENTATION = [ipaddress.ip_network(n) for n in
                           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8",
                            "2001:db8::/32", "::1/128")]
HORODATAGE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?[+-]\d\d:\d\d ")
# L'étiquette syslog, TROISIÈME champ : c'est elle, et elle seule, qui dit qui a écrit la ligne.
FAMILLE = re.compile(r"^\S+ \S+ (?:(?P<dovecot>dovecot(?:\[\d+\])?)|(?P<postscreen>postfix/postscreen\[\d+\])"
                     r"|(?P<smtpd>postfix(?:/[\w.-]+)*/smtpd\[\d+\])|(?P<smtp>postfix(?:/[\w.-]+)*/smtp\[\d+\])): ")
SERVICE_DE_LA_FAMILLE = {"dovecot": "dovecot", "postscreen": "postscreen", "smtpd": "postfix", "smtp": "postfix"}
QUADRUPLET = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])")
SUITE_HEXA = re.compile(r"[0-9A-Fa-f:.]+")
UTILISATEUR = re.compile(r"user=<([^>]*)>")
SERVICE_DOVECOT = re.compile(r"^\S+ \S+ dovecot(?:\[\d+\])?: ([a-z0-9]+)-login: ")
FONCTIONS_D_ADRESSE = ("est_ipv4", "est_ipv6", "adresse")
# `(valeur lue, adresse rendue)` ; "" = pas une adresse. Les valeurs rendues sont relues par
# `ipaddress` avant usage : la table ne peut pas attendre une forme que Python refuse.
TABLE_DES_ADRESSES = [
    ("192.0.2.40", "192.0.2.40"), ("::ffff:192.0.2.40", "192.0.2.40"), ("2001:db8::5", "2001:db8::5"),
    ("2001:db8:0:1::25", "2001:db8:0:1::25"), ("::1", "::1"), ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
    ("2001:db8::192.0.2.1", "2001:db8::192.0.2.1"),
    ("2001", ""), ("1457", ""), ("2001:db8", ""), ("2001:db8::5::1", ""), ("1:2:3:4:5:6:7:8:9", ""),
    ("1:2:3:4:5:6:7:8::", ""), (":1::2", ""), ("12345::1", ""), ("fe80::1%eth0", ""),
    ("IPv6:2001:db8::1", ""), ("::ffff:192.0.2", ""), ("192.0.2.256", ""), ("192.0.2.040", ""),
    ("192.0.2", ""), ("mail.example.test", ""), ("", ""),
]


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — la garde REFUSE DE CONCLURE, rien n'a été mesuré.")
    sys.exit(2)


# --- LES CORPUS ----------------------------------------------------------------------------------
def adresses_de_la_ligne(ligne):
    """`(adresses, quadruplets illisibles)` : toute adresse que la ligne porte — quadruplets IPv4, et
    suites hexadécimales à deux-points que `ipaddress` accepte (un horodatage n'en est pas une).
    `IPv6:` est détaché, pour que `[IPv6:2001:db8::1]` soit lu lui aussi."""
    vues, illisibles = [], []
    for q in QUADRUPLET.findall(ligne):
        a = _adresse_ou_rien(q)
        if a is None:
            illisibles.append(q)
        else:
            vues.append(a)
    for s in SUITE_HEXA.findall(ligne.replace("IPv6:", "IPv6 ")):
        if s.count(":") >= 2:
            a = _adresse_ou_rien(s)
            a = a if a is not None else _adresse_ou_rien(s.rstrip(".:"))
            if a is not None:
                vues.append(a)
    return vues, illisibles


def _adresse_ou_rien(s):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def de_documentation(a):
    a = a.ipv4_mapped or a if a.version == 6 else a
    return any(a in p for p in PLAGES_DE_DOCUMENTATION)


def analyser_ligne(n, texte, spec):
    """Rend `(entrée, fautes)` pour une ligne de corpus — la validation, écrite une fois pour les deux."""
    colonnes = texte.split("\t")
    if len(colonnes) != 5:
        return None, [f"ligne {n} : {len(colonnes)} colonnes au lieu de 5"]
    verdict, user, ip, provenance, ligne = colonnes
    fautes = []
    if verdict not in spec["verdicts"]:
        fautes.append(f"ligne {n} : verdict `{verdict}` hors vocabulaire {list(spec['verdicts'])}")
    if provenance not in spec["provenances"]:
        fautes.append(f"ligne {n} : provenance `{provenance}` hors vocabulaire")
    if not HORODATAGE.match(ligne):
        fautes.append(f"ligne {n} : pas d'horodatage ISO avec décalage en tête — le capteur l'ignorerait")
    f = FAMILLE.match(ligne)
    famille = f.lastgroup if f else None
    if famille is None:
        fautes.append(f"ligne {n} : étiquette syslog non reconnue en troisième champ")
    elif provenance in spec["provenances"] and (famille == "dovecot") != (spec["provenances"][provenance] == "dovecot"):
        fautes.append(f"ligne {n} : provenance `{provenance}` sur une ligne `{famille}`")
    if verdict == "succes" and "Login aborted" in ligne:
        fautes.append(f"ligne {n} : une ligne « Login aborted » déclarée `succes` — le corpus légitimerait le défaut qu'il garde")
    if provenance == "client-postfix" and verdict in ("succes", "echec"):
        fautes.append(f"ligne {n} : un texte du client déclaré `{verdict}` — le corpus légitimerait le défaut qu'il garde")
    attendu_user = "" if user == "-" else user
    if famille == "dovecot":
        u = UTILISATEUR.search(ligne)
        u_ligne = u.group(1) if u else ""
        if attendu_user != u_ligne:
            fautes.append(f"ligne {n} : `user` attendu `{user}` ≠ `user=<{u_ligne}>` de la ligne")
        if u_ligne and not u_ligne.endswith("@example.test") and not provenance.startswith("fabriquee-"):
            fautes.append(f"ligne {n} : utilisateur `{u_ligne}` hors de `example.test`")
    elif user != "-":
        fautes.append(f"ligne {n} : `user` attendu `{user}` sur une ligne Postfix — le capteur n'y en lit aucun, "
                      "et l'attendre légitimerait un champ écrit par le client")
    if verdict == "aucun":
        if ip != "-":
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` sur une ligne `aucun`")
    else:
        a = _adresse_ou_rien(ip)
        if a is None:
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` n'est pas une adresse")
        elif a.version == 6 and a.ipv4_mapped:
            fautes.append(f"ligne {n} : `src_ip` attendu sous la forme mappée `{ip}` — le capteur la rend en IPv4")
        elif famille == "dovecot" and f"rip={ip}," not in ligne and f"rip=::ffff:{ip}," not in ligne:
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` absent des champs `rip=` de la ligne")
        elif famille not in (None, "dovecot") and f"[{ip}]" not in ligne:
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` absent des crochets de la ligne")
    adresses, illisibles = adresses_de_la_ligne(ligne)
    for q in illisibles:
        fautes.append(f"ligne {n} : `{q}` n'est pas une adresse")
    for a in adresses:
        if not de_documentation(a):
            fautes.append(f"ligne {n} : adresse `{a}` hors des plages de documentation — une vraie adresse n'a rien à faire ici")
    s = SERVICE_DOVECOT.search(ligne)
    entree = dict(n=n, corpus=spec["nom"], verdict=verdict, user=attendu_user, ip=ip, provenance=provenance,
                  version=("2.4" if "2.4" in provenance else "2.3" if "2.3" in provenance else None),
                  famille=famille, service=SERVICE_DE_LA_FAMILLE.get(famille),
                  login=(s.group(1) if s else None), ligne=ligne)
    return entree, fautes


def lire_corpus(chemin, spec, vues):
    try:
        brut = open(chemin, encoding="utf-8").read().splitlines()
    except OSError as e:
        refus(f"corpus `{os.path.relpath(chemin, RACINE)}` illisible ({e})")
    entrees, fautes = [], []
    for n, texte in enumerate(brut, 1):
        if not texte.strip() or texte.startswith("#"):
            continue
        entree, f = analyser_ligne(n, texte, spec)
        fautes += f
        if entree is None:
            continue
        if entree["ligne"] in vues:
            fautes.append(f"ligne {n} : ligne en double (dans ce corpus ou dans l'autre)")
        vues.add(entree["ligne"])
        entrees.append(entree)
    if fautes:
        for f in fautes:
            print(f"::error file={os.path.relpath(chemin, RACINE)}::{ETIQUETTE} : {f}")
        refus(f"corpus `{spec['nom']}` invalide ({len(fautes)} faute(s))")
    return entrees


def plancher_dovecot(entrees):
    manques = []
    for version in ("2.3", "2.4"):
        for verdict in ("succes", "echec", "aucun"):
            if not any(e["version"] == version and e["verdict"] == verdict for e in entrees):
                manques.append(f"aucun `{verdict}` {version}")
        if not any(e["provenance"] == f"fabriquee-{version}" for e in entrees):
            manques.append(f"aucun témoin d'ancrage {version} (`fabriquee-{version}`)")
    for provenance, verdict in (("mesuree-2.4.1", "succes"), ("mesuree-2.4.1", "echec"), ("mesuree-2.3.19.1", "succes")):
        if not any(e["provenance"] == provenance and e["verdict"] == verdict for e in entrees):
            manques.append(f"la ligne MESURÉE `{verdict}` `{provenance}` du constat a disparu")
    for service in SERVICES_DE_CONNEXION:
        if not any(e["version"] == "2.4" and e["verdict"] == "succes" and e["login"] == service for e in entrees):
            manques.append(f"aucun succès 2.4 de `{service}-login`")
    if not any("Login aborted" in e["ligne"] and e["verdict"] != "succes" for e in entrees):
        manques.append("aucune ligne « Login aborted » : la propriété centrale n'est pas exercée")
    return manques


def _client(e, texte):
    return e["provenance"] == "client-postfix" and texte in e["ligne"]


# Le plancher du corpus frère, EXIGENCE PAR EXIGENCE : chacune est une ligne que le capteur d'avant
# classait faux, ou un vrai échec que l'ancrage ne doit pas perdre.
EXIGENCES_CLIENT = [
    ("P10.22-s : un succès Dovecot depuis une adresse IPv6",
     lambda e: e["famille"] == "dovecot" and e["verdict"] == "succes" and ":" in e["ip"]),
    ("P10.22-s : un `rip=::ffff:` rendu en IPv4",
     lambda e: "rip=::ffff:" in e["ligne"] and e["verdict"] != "aucun" and ":" not in e["ip"]),
    ("P10.22-s : un `rip=` écrit par le client avant celui du serveur",
     lambda e: e["famille"] == "dovecot" and "rip=" in e["user"]),
    ("P10.22-s : un échec SASL Postfix depuis une adresse IPv4",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and ":" not in e["ip"]),
    ("P10.22-s : un échec SASL Postfix depuis une adresse IPv6",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and ":" in e["ip"]),
    ("P10.22-s : un client smtpd journalisé avec son port (`nom[adresse]:port`)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] != "aucun" and re.search(r"\]:\d+: ", e["ligne"])),
    ("P10.22-s : un client postscreen IPv6 `[adresse]:port`",
     lambda e: e["famille"] == "postscreen" and e["verdict"] != "aucun" and ":" in e["ip"]),
    ("P10.22-s : un littéral d'adresse `helo=<[…]>` écrit par le client, jamais pris",
     lambda e: e["verdict"] != "aucun" and "helo=<[" in e["ligne"] and f"helo=<[{e['ip']}]>" not in e["ligne"]),
    ("P10.22-s : un `[IPv6:…]` écrit par le client", lambda e: "[IPv6:" in e["ligne"]),
    ("échappement JSON : un octet journalisé en octal (`\\ooo`)",
     lambda e: e["verdict"] != "aucun" and re.search(r"\\[0-7][0-7][0-7]", e["ligne"])),
    ("P10.22-v : un échec SASL Postfix AVEC `, sasl_username=` (3.9 et après)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and ", sasl_username=" in e["ligne"]),
    ("P10.22-v : un échec SASL Postfix SANS `, sasl_username=` (avant 3.9)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and "sasl_username=" not in e["ligne"]),
    ("P10.22-v : `auth failed` écrit par le client", lambda e: _client(e, "auth failed")),
    ("P10.22-v : `authentication failed` écrit par le client", lambda e: _client(e, "authentication failed")),
    ("P10.22-v : `Aborted login` écrit par le client", lambda e: _client(e, "Aborted login")),
    ("P10.22-v : l'étiquette ` dovecot: ` écrite par le client", lambda e: _client(e, " dovecot: ")),
    ("P10.22-v : un `rip=` écrit par le client", lambda e: _client(e, "rip=")),
    ("P10.22-v : un `user=<…>` écrit par le client", lambda e: _client(e, "user=<")),
    ("P10.22-v : un texte du client dans une pré-salutation postscreen",
     lambda e: _client(e, "PREGREET") and e["famille"] == "postscreen"),
    ("P10.22-v : l'échec SASL du relais SORTANT, jamais compté",
     lambda e: e["famille"] == "smtp" and "SASL authentication failed" in e["ligne"] and e["verdict"] == "aucun"),
]


def plancher_client(entrees):
    return [nom for nom, vrai in EXIGENCES_CLIENT if not any(vrai(e) for e in entrees)]


def epreuve_de_la_validation():
    """La validation, éprouvée sur des lignes FABRIQUÉES : la conforme passe, chaque écart est refusé."""
    tete = "2026-09-23T19:00:00.000000+02:00 mailserver "
    conforme = ("rejet\t-\t2001:db8::7\tclient-postfix\t" + tete + "postfix/smtpd[1]: NOQUEUE: reject: RCPT from "
                "unknown[2001:db8::7]: 554 5.7.1 <b@example.test>: Relay access denied; from=<a@example.test> "
                "to=<b@example.test> proto=ESMTP helo=<auth failed>")
    _, f = analyser_ligne(1, conforme, SPEC_CLIENT)
    if f:
        return f"une ligne CONFORME est refusée : {f}"
    ecarts = {
        "une adresse IPv6 hors de la plage de documentation": conforme.replace("helo=<auth failed>", "helo=<[2001:4860::8888]>"),
        "une adresse attendue sous la forme mappée": conforme.replace("\t2001:db8::7\t", "\t::ffff:192.0.2.7\t"),
        "un utilisateur attendu sur une ligne Postfix": conforme.replace("rejet\t-\t", "rejet\tb@example.test\t"),
        "un texte du client déclaré échec": conforme.replace("rejet\t", "echec\t", 1),
        "une adresse attendue absente des crochets": conforme.replace("\t2001:db8::7\t", "\t2001:db8::8\t"),
        "une provenance Dovecot sur une ligne Postfix": conforme.replace("\tclient-postfix\t", "\tsources-2.4.1\t"),
    }
    for nom, ligne in ecarts.items():
        if not analyser_ligne(1, ligne, SPEC_CLIENT)[1]:
            return f"la validation laisse passer « {nom} »"
    return None


# --- LE JUGE -------------------------------------------------------------------------------------
def juger(entrees, evenements):
    fautes = []
    par_message = {}
    for ev in evenements:
        par_message.setdefault(ev.get("message"), []).append(ev)
    for e in entrees:
        vus = par_message.pop(e["ligne"], [])
        classe = CLASSE_DU_VERDICT[e["verdict"]]
        quoi = f"{e['corpus']} ligne {e['n']} ({e['provenance']}, attendu `{e['verdict']}`)"
        if classe is None:
            if vus:
                fautes.append(f"{quoi} : {len(vus)} événement(s) émis, `{vus[0].get('category')}`/`{vus[0].get('fields', {}).get('action')}`")
            continue
        if len(vus) != 1:
            fautes.append(f"{quoi} : {len(vus)} événement(s) au lieu d'un — ligne non classée")
            continue
        ev = vus[0]
        champs = ev.get("fields") or {}
        if (ev.get("category"), champs.get("action")) != classe:
            fautes.append(f"{quoi} : classée `{ev.get('category')}`/`{champs.get('action')}` au lieu de `{classe[0]}`/`{classe[1]}`")
        if champs.get("user") != e["user"]:
            fautes.append(f"{quoi} : `user` = `{champs.get('user')}` au lieu de `{e['user']}`")
        if ev.get("src_ip") != e["ip"] or champs.get("src_ip") != e["ip"]:
            fautes.append(f"{quoi} : `src_ip` = `{ev.get('src_ip')}`/`{champs.get('src_ip')}` au lieu de `{e['ip']}`")
        if champs.get("service") != e["service"]:
            fautes.append(f"{quoi} : `service` = `{champs.get('service')}` au lieu de `{e['service']}`")
    for message, vus in par_message.items():
        fautes.append(f"{len(vus)} événement(s) pour un message absent des corpus : `{str(message)[:120]}`")
    return fautes


def epreuve_du_juge():
    """Témoins sur des événements FABRIQUÉS : le juge doit se taire sur l'exact et accuser chaque écart."""
    def ev(ligne, cat, action, user, ip, service):
        return {"source": "mail", "category": cat, "src_ip": ip, "message": ligne,
                "fields": {"action": action, "user": user, "src_ip": ip, "service": service}}
    def entree(n, verdict, user, ip, service, ligne):
        return dict(n=n, corpus="x", verdict=verdict, user=user, ip=ip, provenance="x", service=service, ligne=ligne)
    corpus = [
        entree(1, "succes", "a@example.test", "192.0.2.1", "dovecot", "L1"),
        entree(2, "echec", "b@example.test", "192.0.2.2", "dovecot", "L2"),
        entree(3, "aucun", "", "-", "postfix", "L3"),
        entree(4, "rejet", "", "2001:db8::4", "postfix", "L4"),
    ]
    exact = [ev("L1", "auth", "success", "a@example.test", "192.0.2.1", "dovecot"),
             ev("L2", "auth", "failure", "b@example.test", "192.0.2.2", "dovecot"),
             ev("L4", "reject", "blocked", "", "2001:db8::4", "postfix")]
    if juger(corpus, exact):
        return f"le juge accuse le résultat EXACT : {juger(corpus, exact)}"
    ecarts = {
        "succès manquant": exact[1:],
        "succès rendu en échec": [ev("L1", "auth", "failure", "a@example.test", "192.0.2.1", "dovecot")] + exact[1:],
        "rejet rendu en échec": exact[:2] + [ev("L4", "auth", "failure", "", "2001:db8::4", "postfix")],
        "événement pour une ligne `aucun`": exact + [ev("L3", "auth", "failure", "", "192.0.2.3", "postfix")],
        "`user` faux": [ev("L1", "auth", "success", "z@example.test", "192.0.2.1", "dovecot")] + exact[1:],
        "`src_ip` faux": exact[:2] + [ev("L4", "reject", "blocked", "", "198.51.100.9", "postfix")],
        "`service` faux": exact[:2] + [ev("L4", "reject", "blocked", "", "2001:db8::4", "dovecot")],
        "événement inventé": exact + [ev("L9", "auth", "success", "a@example.test", "192.0.2.1", "dovecot")],
    }
    for nom, evenements in ecarts.items():
        if not juger(corpus, evenements):
            return f"le juge n'accuse pas « {nom} »"
    return None


# --- LE CAPTEUR, EXÉCUTÉ -------------------------------------------------------------------------
def implementations_awk():
    trouvees, chemins = [], set()
    for nom in AWK_EXERCES:
        chemin = shutil.which(nom)
        if chemin and os.path.realpath(chemin) not in chemins:
            chemins.add(os.path.realpath(chemin))
            trouvees.append((nom, chemin))
    return trouvees


def fonctions_d_adresse_livrees():
    """`(texte, introuvables)` : le TEXTE des fonctions d'adresse de `collectors/mail.sh`, de
    `function <nom>(` à la ligne `}` qui la ferme — le code livré, jamais une copie."""
    lignes = open(CAPTEUR, encoding="utf-8").read().split("\n")
    blocs, introuvables = [], []
    for nom in FONCTIONS_D_ADRESSE:
        debut = next((i for i, l in enumerate(lignes) if l.startswith(f"function {nom}(")), None)
        fin = next((i for i in range(debut or 0, len(lignes)) if lignes[i] == "}"), None) if debut is not None else None
        if debut is None or fin is None:
            introuvables.append(nom)
        else:
            blocs.append("\n".join(lignes[debut:fin + 1]))
    return "\n".join(blocs), introuvables


def epreuve_des_adresses(chemin_awk, fonctions):
    for lu, rendu in TABLE_DES_ADRESSES:
        if rendu and (_adresse_ou_rien(rendu) is None or ipaddress.ip_address(rendu) != (
                lambda a: a.ipv4_mapped or a if a.version == 6 else a)(ipaddress.ip_address(lu))):
            refus(f"table des adresses incohérente : `{lu}` -> `{rendu}` n'est pas ce que `ipaddress` lit")
    with tempfile.TemporaryDirectory(prefix="garde-mail-adresses-") as bac:
        programme, cas = os.path.join(bac, "adresses.awk"), os.path.join(bac, "cas")
        open(programme, "w", encoding="utf-8").write(fonctions + '\n{ print "[" adresse($0) "]" }\n')
        open(cas, "w", encoding="utf-8").write("".join(lu + "\n" for lu, _ in TABLE_DES_ADRESSES))
        r = subprocess.run([chemin_awk, "-f", programme, cas], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            refus(f"les fonctions d'adresse n'ont pas tourné sous `{chemin_awk}` : {r.stderr.strip()[:300]}")
        rendus = r.stdout.split("\n")[:len(TABLE_DES_ADRESSES)]
    return [f"`adresse(\"{lu}\")` = `{obtenu[1:-1]}` au lieu de `{rendu}`"
            for (lu, rendu), obtenu in zip(TABLE_DES_ADRESSES, rendus) if obtenu != f"[{rendu}]"]


def lancer(chemin_awk, entrees):
    with tempfile.TemporaryDirectory(prefix="garde-mail-dovecot-") as bac:
        rep = {d: os.path.join(bac, d) for d in ("bin", "spool", "state")}
        for d in rep.values():
            os.makedirs(d)
        os.symlink(chemin_awk, os.path.join(rep["bin"], "awk"))
        journal = os.path.join(bac, "mail.log")
        with open(journal, "w", encoding="utf-8") as fh:
            fh.write("".join(e["ligne"] + "\n" for e in entrees))
        env = {k: v for k, v in os.environ.items() if not k.startswith("PLUME_")}
        env.update(
            PATH=rep["bin"] + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            PLUME_LIB=LIB, PLUME_SPOOL=rep["spool"], PLUME_STATE=rep["state"],
            PLUME_MAIL_SRC="file", PLUME_MAIL_LOG=journal, PLUME_MAIL_MAX=str(len(entrees) + 10),
        )
        r = subprocess.run(["sh", CAPTEUR], env=env, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            refus(f"le capteur a échoué sous `{chemin_awk}` (rc={r.returncode}) : {r.stderr.strip()[:300]}")
        evenements, enveloppes = [], 0
        for nom in sorted(os.listdir(rep["spool"])):
            if nom.startswith(".") or not nom.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(rep["spool"], nom), encoding="utf-8"))
            except (OSError, ValueError) as e:
                # Pas un refus : c'est le capteur qui a écrit une enveloppe que le démon ne lira pas.
                return None, f"enveloppe `{nom}` illisible comme JSON ({e}) — tout le passage est perdu"
            if doc.get("kind") != "events":
                continue
            enveloppes += 1
            evenements += [ev for ev in doc.get("events") or [] if ev.get("category") != "config"]
        if enveloppes == 0:
            refus(f"le capteur n'a déposé aucune enveloppe d'événements sous `{chemin_awk}`")
        return evenements, None


def main():
    for f in (CAPTEUR, LIB, CORPUS_DOVECOT, CORPUS_CLIENT):
        if not os.path.exists(f):
            refus(f"`{os.path.relpath(f, RACINE)}` introuvable")
    if shutil.which("sh") is None:
        refus("aucun `sh`")
    for epreuve, quoi in ((epreuve_du_juge, "juge"), (epreuve_de_la_validation, "validation des corpus")):
        faute = epreuve()
        if faute:
            refus(f"instrument INVALIDE ({quoi}) — {faute}")
    vues = set()
    dovecot = lire_corpus(CORPUS_DOVECOT, SPEC_DOVECOT, vues)
    client = lire_corpus(CORPUS_CLIENT, SPEC_CLIENT, vues)
    manques = [f"{SPEC_DOVECOT['nom']} : {m}" for m in plancher_dovecot(dovecot)] + \
              [f"{SPEC_CLIENT['nom']} : {m}" for m in plancher_client(client)]
    if manques:
        refus("corpus sous son plancher : " + " ; ".join(manques))
    entrees = dovecot + client
    awks = implementations_awk()
    if not awks:
        refus(f"aucune implémentation d'awk parmi {AWK_EXERCES}")
    # Des fonctions d'adresse introuvables empêchent CETTE épreuve, pas le jugement du corpus : un défaut
    # de classification mesuré l'emporte (1) ; sans défaut, leur absence fait refuser (2).
    fonctions, introuvables = fonctions_d_adresse_livrees()
    total = 0
    for nom, chemin in awks:
        fautes = [] if introuvables else epreuve_des_adresses(chemin, fonctions)
        evenements, illisible = lancer(chemin, entrees)
        fautes += [illisible] if illisible else juger(entrees, evenements)
        for f in fautes:
            print(f"::error file=collectors/mail.sh::{ETIQUETTE} ({nom}) : {f}")
        total += len(fautes)
    exerces = ", ".join(n for n, _ in awks)
    absents = ", ".join(n for n in AWK_EXERCES if n not in {n for n, _ in awks})
    if total:
        print(f"{ETIQUETTE} : {total} défaut(s) sur {len(entrees)} lignes et {len(TABLE_DES_ADRESSES)} adresses (awk exercés : {exerces})"
              + (f" ; fonctions d'adresse introuvables, table NON jouée : {', '.join(introuvables)}." if introuvables else "."))
        sys.exit(1)
    if introuvables:
        refus(f"fonction(s) d'adresse introuvable(s) dans `collectors/mail.sh` : {', '.join(introuvables)}")
    par_version = {v: sum(1 for e in dovecot if e["version"] == v) for v in ("2.3", "2.4")}
    print(f"{ETIQUETTE} : le capteur mail LIVRÉ classe les {len(dovecot)} lignes Dovecot "
          f"({par_version['2.4']} en 2.4, {par_version['2.3']} en 2.3) et les {len(client)} lignes d'adresses et de "
          f"texte du client ({len(EXIGENCES_CLIENT)} exigences de plancher) comme attendu — succès lus à l'en-tête "
          f"Dovecot, « Login aborted » et texte du client jamais verdict d'authentification, adresse entière "
          f"(IPv6, mappée rendue en IPv4), {len(TABLE_DES_ADRESSES)} valeurs d'adresse jugées, rien d'inventé. "
          f"Awk exercés : {exerces}" + (f" ; NON EXERCÉS (absents) : {absents}." if absents else "."))
    sys.exit(0)


if __name__ == "__main__":
    main()
