#!/usr/bin/env python3
"""Le capteur mail masque chaque partie locale qu'il émet, sur TOUTE ligne et dans chaque champ — garde de CI
(`P10.32-l`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`collectors/mail.sh` n'appliquait `masquer_adresses` qu'au courrier SORTANT (`postfix/smtp`). Partout
ailleurs la ligne brute partait telle quelle — `user=<…@…>` de Dovecot, `from=<…> to=<…>` d'un rejet,
`<expéditeur> -> <destinataire>` d'amavis, `envelope-from=` de policyd-spf, `sasl_username=` de smtpd — et
les champs `user`, `sender`, `rcpt` portaient l'adresse complète. Un rôle `viewer`, ou une base volée,
lisait ainsi l'annuaire des correspondants de chaque boîte du serveur.

CE QUE LA GARDE FAIT
--------------------
Elle exécute le capteur TEL QU'IL EST LIVRÉ, en mode fichier, dans un bac (spool, état, journal à lui),
sous CHAQUE awk présent parmi `gawk` et `mawk`, sur deux journaux :
  * des lignes FABRIQUÉES, une par famille que le capteur émet (connexion et échec Dovecot, échec et succès
    SASL de smtpd, rejet, amavis entrant et ORIGINAIRE, file, sortant, SPF), dont chaque partie locale est
    un MARQUEUR unique — dont une valeur sans `@` (`user=<…>`) et des parties locales à espace non
    guillemetées, la limite dite de `P10.32-f`, dans chaque valeur LUE (compte Dovecot, destinataire du
    sortant, expéditeur de la file active et expirée, expéditeur et destinataire d'amavis). Chaque ligne doit donner EXACTEMENT un événement (un
    capteur muet ne passe pas), aucun marqueur ne doit figurer dans l'événement (message, champs, clé),
    les champs `user`, `sender`, `rcpt` valent la forme masquée attendue, et l'étiquette `clé=` collée à
    une partie locale reste lisible (`sasl_username=*@…`, `envelope-from=*@…`) — une ÉTIQUETTE seulement :
    un `nom=` entre chevrons (`to=<a_b=c@…>`), après `(`, ou la signature BATV (`envelope-from=prvs=…=x@…`)
    est masqué avec la partie locale ;
  * toutes les lignes des corpus mail livrés (`collectors/mail-*.corpus`, hors ClamAV) : dans chaque
    événement émis, aucune partie locale autre que `*` devant un `@` du message, et `user`, `sender`,
    `rcpt` vides, `*` ou `*@<domaine>`.
UNE EXCEPTION, ÉCRITE ET ADOSSÉE À SA RÈGLE : l'expéditeur d'une entrée amavis ORIGINAIRE (`LOCAL`) reste
en clair dans `sender` — jamais dans le message —, parce que la règle livrée `ex-mail-mass-outbound`
compte `sender` par expéditeur (`stats count by sender`) : masqué, le compte d'un serveur se confondrait
avec tous les envois du domaine. La garde LIT la règle : si elle ne groupe plus par `sender` sur
`service=amavis`, l'exception n'a plus de raison, et c'est une faute.

CODES : 0 tout est tenu ; 1 un défaut mesuré ; 2 la garde refuse de conclure (juge non discriminant, aucun
awk, capteur en échec, corpus ou règle illisibles) — rien n'a été mesuré.

CE QU'ELLE NE TIENT PAS, DIT
----------------------------
Une partie locale à espace que le capteur ne LIT pas (texte libre d'un serveur distant, `<jean dupont@d>`
hors de la valeur lue) sort encore `<jean *@d>` : aucune borne lisible ne la sépare du texte. De même une
partie locale qui contient `=`, HORS chevrons et sans étiquette devant (` jean_dupont=x@d` rend
` jean_dupont=*@d`) : rien ne la distingue d'une étiquette de champ. Le domaine
est gardé à dessein. Le compte d'une entrée `LOCAL` est l'adresse que le client authentifié a donnée
(une banque de politique nommée `LOCAL` sans le drapeau `%l` serait lue comme originaire). Les lignes
fabriquées ne sont pas relevées dans un journal réel ; leurs formes sont celles des corpus livrés.

LE DESTINATAIRE LOCAL D'UN VIRUS OU D'UNE PIÈCE BANNIE (`P10.33-f`, décidé par l'exploitant : « configurable,
masqué par défaut »)
-------------------------------------------------------------------------------------------------------------
`PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL=1` rend en clair le champ `rcpt` d'un verdict INFECTED (`malware`) ou
BANNED (`banned`) dont le domaine figure dans `PLUME_MAIL_DOMAINES_LOCAUX` — et RIEN d'autre. La garde joue le
capteur sous DOUZE réglages (absent, `0`, `1` avec liste, `1` sans liste, `1` avec une liste illisible, `1` avec
une liste en partie illisible, une valeur autre que `0`/`1`, `1` avec la seule liste `mail.example.test` dont
les boîtes du domaine PARENT `example.test` restent masquées, `1` avec un point final, un point en tête, un
double point, un motif `*`) sur les lignes fabriquées ci-dessus PLUS des entrées amavis vers un domaine local,
un domaine externe, un sous-domaine du domaine local, un domaine PRÉFIXE d'un domaine local (`@example`), un
domaine à espace fait de deux domaines locaux, une valeur sans `@` égale à un domaine local, sur INFECTED,
BANNED, CLEAN et SPAM. Le capteur tourne dans un répertoire courant PIÉGÉ (un fichier au nom de domaine
lisible), éprouvé d'abord : un motif de la liste qu'un shell développerait y rendrait un domaine. Seul le `rcpt` d'un INFECTED ou BANNED local sort en clair, et seulement réglage à `1`
avec liste ; la boîte démasquée ne sort NI dans le message, NI dans `user`, NI dans la clé ; sans liste
lisible ou sur une valeur illisible, rien n'est démasqué et un aveu `fallback`/`unreadable-config` le dit ;
l'enveloppe de config dit l'état (`destinataire_local`) et la liste RETENUE (`domaines_locaux` : minuscules,
sans doublon ni entrée illisible). Le corpus livré est rejoué réglage actif : un `rcpt`
en clair n'y est admis que sur `malware`/`banned` d'un domaine local, et il doit y en avoir au moins un.
CE QU'ELLE NE TIENT PAS, DIT : « local » est la liste DÉCLARÉE ; une liste fausse démasque des boîtes qui ne
sont pas de ce serveur, et la garde ne peut pas le savoir.
"""
import datetime
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
REGLE = os.path.join(RACINE, "config.d", "rules", "catalog", "ex-mail-mass-outbound.json")
ETIQUETTE = "P10.32-l"
AWK_EXERCES = ("gawk", "mawk")
CORPUS_CLAMAV = ("mail-clamd.corpus", "mail-freshclam.corpus")

# Une partie locale restante : ce qui précède un `@` jusqu'à une espace, un `<`, un autre `@` ou le début,
# l'étiquette de champ mise à part (`_etiquette` : au début du morceau ou après `,`/`;`, JAMAIS après un `<`
# ou un `@`) — `*` après masquage, ou rien. `to=<jean_dupont=*@d>` est donc une partie locale restante.
PARTIE_LOCALE_RESTANTE = re.compile(r"[^ <@]+@")
ETIQUETTE_DE_CHAMP = re.compile(r"(?:^|[,;])[A-Za-z_-]+=")
FORME_MASQUEE = re.compile(r"^(|\*|\*@[^@ ]*)$")
AMAVIS_ORIGINAIRE = re.compile(r"[{][A-Za-z,]*[}], (?:[A-Za-z0-9_./-]+ )?LOCAL \[[0-9A-Fa-f:.]+\]:[0-9]+ ")
COMPTE_LOCAL = "comptelocal@example.test"
ETIQUETTE_LOCAL = "P10.33-f"
REGLAGE_LOCAL = "PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL"
LISTE_LOCALE = "PLUME_MAIL_DOMAINES_LOCAUX"


def _h(s):
    return f"2026-10-14T06:00:{s:02d}.000000+00:00 mx1 "


# (ligne, champs attendus, sous-chaînes attendues dans le message). Chaque `marq…` est un marqueur unique.
FABRIQUEES = [
    (_h(1) + "dovecot: imap-login: Login: user=<marqa@example.test>, method=PLAIN, rip=192.0.2.21, lip=192.0.2.1, "
             "mpid=1, TLS, session=<Zml4MDE>",
     {"user": "*@example.test"}, ["user=<*@example.test>"]),
    (_h(2) + "dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<marqb>, method=PLAIN, "
             "rip=192.0.2.22, lip=192.0.2.1, TLS, session=<Zml4MDI>",
     {"user": "*"}, ["user=<*>"]),
    (_h(3) + "dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<marqc suite@example.test>, "
             "method=PLAIN, rip=192.0.2.23, lip=192.0.2.1, TLS, session=<Zml4MDM>",
     {"user": "*@example.test"}, ["user=<*@example.test>"]),
    (_h(4) + "postfix/submission/smtpd[3001]: warning: unknown[192.0.2.24]: SASL LOGIN authentication failed: "
             "UGFzc3dvcmQ6, sasl_username=marqd@example.test",
     {"user": "*@example.test"}, ["sasl_username=*@example.test"]),
    (_h(5) + "postfix/submission/smtpd[3002]: 5A2B3C4D5E1: client=unknown[192.0.2.25], sasl_method=PLAIN, "
             "sasl_username=marqe@example.test",
     {"user": "*@example.test"}, ["sasl_username=*@example.test"]),
    (_h(6) + "postfix/smtpd[3003]: NOQUEUE: reject: RCPT from unknown[192.0.2.26]: 554 5.7.1 <marqg@example.test>: "
             "Relay access denied; from=<marqf@example.net> to=<marqg@example.test> proto=ESMTP helo=<x.example.net>",
     {"user": ""}, ["from=<*@example.net> to=<*@example.test>"]),
    (_h(7) + "amavis[4001]: (04001-01) Passed CLEAN {RelayedInbound}, [192.0.2.27]:40001 <marqh@example.net> -> "
             "<marqi@example.test>, Queue-ID: 4ABCDEF001, Message-ID: <m001@example.net>, mail_id: AbCdEfGh0001, "
             "Hits: -1.1, size: 2345, queued_as: 4BCDEF3001, 120 ms",
     {"user": "*@example.test", "sender": "*@example.net", "rcpt": "*@example.test"}, ["<*@example.net> -> <*@example.test>"]),
    (_h(8) + "amavis[4002]: (04002-01) Passed CLEAN {RelayedOutbound}, ORIGINATING LOCAL [192.0.2.28]:40002 "
             f"<{COMPTE_LOCAL}> -> <marqj@example.net>, Queue-ID: 4ABCDEF002, Message-ID: <m002@example.test>, "
             "mail_id: AbCdEfGh0002, Hits: -, size: 900, queued_as: 4BCDEF3002, 120 ms",
     {"user": "*@example.net", "sender": COMPTE_LOCAL, "rcpt": "*@example.net"}, ["<*@example.test> -> <*@example.net>"]),
    (_h(9) + "postfix/qmgr[3004]: 4A1B2C3D4E9: from=<marqk@example.net>, size=1234, nrcpt=1 (queue active)",
     {"sender": "*@example.net"}, ["from=<*@example.net>"]),
    (_h(10) + "postfix/smtp[3005]: 4A1B2C3D4EA: to=<marql suite@example.org>, relay=mx.example.org[198.51.100.5]:25, "
              "delay=1, delays=0.1/0/0.5/0.4, dsn=2.0.0, status=sent (250 2.0.0 <marql suite@example.org> accepted)",
     {"user": "", "rcpt_domain": "example.org"}, ["to=<*@example.org>", "(250 2.0.0 <*@example.org> accepted)"]),
    (_h(11) + "policyd-spf[3006]: : prepend Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=192.0.2.31; "
              "helo=mx.example.net; envelope-from=marqm@example.net; receiver=example.test ",
     {"user": "", "domain": "example.net"}, ["envelope-from=*@example.net;"]),
    # Les valeurs LUES à partie locale à espace, hors du sortant : seul leur remplacement à leur place
    # (`lu_exp`, `lu_dest` de `masquer_ligne`) les masque — `masquer_adresses` laisserait `<marqn *@…>`.
    (_h(12) + "postfix/qmgr[3007]: 4A1B2C3D4EB: from=<marqn suite@example.net>, size=1234, nrcpt=1 (queue active)",
     {"sender": "*@example.net"}, ["from=<*@example.net>"]),
    (_h(13) + "postfix/qmgr[3008]: 4A1B2C3D4EC: from=<marqo suite@example.net>, status=expired, returned to sender",
     {"sender": "*@example.net"}, ["from=<*@example.net>"]),
    (_h(14) + "amavis[4003]: (04003-01) Passed CLEAN {RelayedInbound}, [192.0.2.29]:40003 <marqp suite@example.net> -> "
              "<marqr suite@example.test>, Queue-ID: 4ABCDEF003, Message-ID: <m003@example.net>, mail_id: AbCdEfGh0003, "
              "Hits: -1.1, size: 2345, queued_as: 4BCDEF3003, 120 ms",
     {"user": "*@example.test", "sender": "*@example.net", "rcpt": "*@example.test"}, ["<*@example.net> -> <*@example.test>"]),
    # Une partie locale qui CONTIENT `nom=`, entre chevrons, sur une ligne dont rien n'est LU (rejet) : seul
    # `masquer_adresses` la masque, et le `nom=` n'y est pas une étiquette (l'ancienne règle rendait
    # `to=<marqt-claire=*@…>`).
    (_h(15) + "postfix/smtpd[3009]: NOQUEUE: reject: RCPT from unknown[192.0.2.32]: 554 5.7.1 "
              "<marqt-claire=y@example.test>: Relay access denied; from=<marqs_dupont=x@example.net> "
              "to=<marqt-claire=y@example.test> proto=ESMTP helo=<x.example.net>",
     {"user": ""}, ["554 5.7.1 <*@example.test>:", "from=<*@example.net> to=<*@example.test>"]),
    # BATV hors chevrons : l'étiquette du champ sort, `prvs=`, la signature et la partie locale non.
    (_h(16) + "policyd-spf[3010]: : prepend Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=192.0.2.33; "
              "helo=mx.example.net; envelope-from=prvs=0123abcd=marqu@example.net; receiver=example.test ",
     {"user": "", "domain": "example.net"}, ["envelope-from=*@example.net;"]),
    # `(` n'est pas une borne d'étiquette : un `nom=` juste après lui est masqué avec la partie locale.
    (_h(17) + "postfix/smtp[3011]: 4A1B2C3D4ED: to=<marqv@example.org>, relay=mx.example.org[198.51.100.6]:25, "
              "delay=1, delays=0.1/0/0.5/0.4, dsn=5.1.1, status=bounced (host mx.example.org[198.51.100.6] said: "
              "550 5.1.1 (marqw_x=y@example.org) unknown user (in reply to RCPT TO command))",
     {"user": "", "rcpt_domain": "example.org"}, ["to=<*@example.org>", "550 5.1.1 *@example.org) unknown user"]),
]
MARQUEUR = re.compile(r"marq[a-z]")


# --- P10.33-f : LE DESTINATAIRE LOCAL ---------------------------------------------------------------
def _h2(s):
    return f"2026-10-14T06:01:{s:02d}.000000+00:00 mx1 "


def _amavis(n, verdict, dest, fin="Hits: -, size: 1234, 45 ms"):
    return (_h2(n) + f"amavis[{4200 + n}]: ({4200 + n:05d}-01) {verdict} {{DiscardedInbound,Quarantined}}, "
            f"[192.0.2.{60 + n}]:{40200 + n} <marqy{n:02d}@example.net> -> <{dest}>, Queue-ID: 4ABCDEF2{n:02d}, "
            f"Message-ID: <m2{n:02d}@example.net>, mail_id: AbCdEfGh2{n:03d}, {fin}")


# (ligne, catégorie attendue, `rcpt` attendu réglage ACTIF avec la liste `example.test`, boîte qui ne doit
# sortir nulle part ailleurs que dans `rcpt`). Réglage inactif, `rcpt` vaut `masquer(dest)` partout. La boîte
# bannie a une partie locale à ESPACE : seul son remplacement à sa place (`lu_dest`) la masque dans le message,
# `masquer_adresses` laisserait `<boitebannie *@…>`.
DESTINATAIRES = [
    (_amavis(1, "Blocked INFECTED (Eicar-Signature)", "boitevirus@example.test"),
     "malware", "boitevirus@example.test", "boitevirus"),
    (_amavis(2, "Blocked BANNED (application/x-msdownload,.exe,.exe-ms,facture.exe)", "boitebannie suite@Example.TEST"),
     "banned", "boitebannie suite@Example.TEST", "boitebannie"),
    (_amavis(3, "Blocked INFECTED (Eicar-Signature)", "marqexterne@example.net"), "malware", "*@example.net", None),
    (_amavis(4, "Blocked BANNED (application/x-msdownload,.exe,.exe-ms,x.exe)", "marqsous@sous.example.test"),
     "banned", "*@sous.example.test", None),
    (_amavis(5, "Passed CLEAN", "marqclean@example.test"), "mailflow", "*@example.test", None),
    (_amavis(6, "Blocked SPAM", "marqspam@example.test"), "mailflow", "*@example.test", None),
    # Un domaine à ESPACE dont les deux mots sont locaux (` example.test example.invalid ` contient
    # ` example.test example.invalid `) : seule la règle « sans espace » le garde masqué.
    (_amavis(7, "Blocked INFECTED (Eicar-Signature)", "marqesp@example.test example.invalid"), "malware",
     "*@example.test example.invalid", None),
    # Une valeur SANS `@` égale à un domaine local : ce n'est pas une adresse, elle sort `*`.
    (_amavis(8, "Blocked INFECTED (Eicar-Signature)", "Example.TEST"), "malware", "*", None),
    # Un domaine PRÉFIXE d'un domaine local (` example.test ` contient ` example`) : seule la borne d'espace
    # DROITE de la comparaison le garde masqué.
    (_amavis(9, "Blocked INFECTED (Eicar-Signature)", "marqprefixe@example"), "malware", "*@example", None),
]
# (nom, réglages, démasque ?, clé avouée ou None, état attendu dans l'enveloppe de config, liste RETENUE
# attendue dans l'enveloppe : `domaines_locaux`, en minuscules, sans doublon ni entrée illisible, `,` entre).
# « Démasque ? » dit si les entrées de DESTINATAIRES vers `example.test` sortent en clair : la liste
# `mail.example.test` démasque (état `demasque`) mais AUCUNE entrée n'est de ce domaine — toutes restent masquées.
REGLAGES_LOCAUX = [
    ("réglage absent, liste posée", {LISTE_LOCALE: "example.test"}, False, None, "masque", ""),
    ("réglage à 0, liste posée", {REGLAGE_LOCAL: "0", LISTE_LOCALE: "example.test"}, False, None, "masque", ""),
    ("réglage à 1, liste posée", {REGLAGE_LOCAL: "1", LISTE_LOCALE: " Example.TEST,example.invalid "}, True, None,
     "demasque", "example.test,example.invalid"),
    ("réglage à 1, sans liste", {REGLAGE_LOCAL: "1"}, False, LISTE_LOCALE, "masque-sans-liste", ""),
    ("réglage à 1, liste illisible", {REGLAGE_LOCAL: "1", LISTE_LOCALE: "*.example.test"}, False, LISTE_LOCALE,
     "masque-sans-liste", ""),
    ("réglage à 1, liste en partie illisible", {REGLAGE_LOCAL: "1", LISTE_LOCALE: "example.test x_y EXAMPLE.test"},
     True, LISTE_LOCALE, "demasque", "example.test"),
    ("réglage à oui", {REGLAGE_LOCAL: "oui", LISTE_LOCALE: "example.test"}, False, REGLAGE_LOCAL, "masque", ""),
    # Les boîtes du domaine PARENT d'un domaine local (` mail.example.test ` contient `example.test `) : seule la
    # borne d'espace GAUCHE de la comparaison les garde masquées.
    ("réglage à 1, liste d'un sous-domaine (boîtes du domaine parent)", {REGLAGE_LOCAL: "1",
     LISTE_LOCALE: "mail.example.test"}, False, None, "demasque", "mail.example.test"),
    # Un point final (notation FQDN), un point en tête, un double point : pas un domaine, avoué.
    ("réglage à 1, liste au point final", {REGLAGE_LOCAL: "1", LISTE_LOCALE: "example.test."}, False, LISTE_LOCALE,
     "masque-sans-liste", ""),
    ("réglage à 1, liste au point en tête", {REGLAGE_LOCAL: "1", LISTE_LOCALE: ".example.test"}, False,
     LISTE_LOCALE, "masque-sans-liste", ""),
    ("réglage à 1, liste au double point", {REGLAGE_LOCAL: "1", LISTE_LOCALE: "example..test"}, False,
     LISTE_LOCALE, "masque-sans-liste", ""),
    # Un motif : le capteur tourne dans un répertoire courant PIÉGÉ (`PIEGE_DU_REPERTOIRE_COURANT`) ; sans
    # `set -f`, `*` deviendrait le nom du piège, un domaine lisible, et la liste démasquerait sans aveu.
    ("réglage à 1, liste réduite à un motif", {REGLAGE_LOCAL: "1", LISTE_LOCALE: "*"}, False, LISTE_LOCALE,
     "masque-sans-liste", ""),
]
# Le nom d'un fichier posé dans le répertoire courant du capteur : un domaine lisible, que tout motif de la liste
# (`*`, `*.example.test`) rendrait s'il était développé.
PIEGE_DU_REPERTOIRE_COURANT = "piege.example.test"


def masquer(v):
    return "*@" + v.rsplit("@", 1)[1] if "@" in v else ("*" if v else "")


def juger_destinataires(evenements, actif):
    fautes, par_ts = [], {}
    for ev in evenements:
        par_ts.setdefault(ev.get("ts"), []).append(ev)
    for ligne, cat, clair, boite in DESTINATAIRES:
        quoi = f"entrée `{ligne[57:90]}…` vers `<{ligne.split(' -> <', 1)[1].split('>', 1)[0]}>`"
        vus = par_ts.get(epoch(ligne), [])
        if len(vus) != 1:
            fautes.append(f"{quoi} : {len(vus)} événement(s) au lieu d'un")
            continue
        ev = vus[0]
        f = ev.get("fields") or {}
        dest = ligne.split(" -> <", 1)[1].split(">", 1)[0]
        attendu = clair if actif else masquer(dest)
        if ev.get("category") != cat:
            fautes.append(f"{quoi} : catégorie `{ev.get('category')}` au lieu de `{cat}`")
        if f.get("rcpt") != attendu:
            fautes.append(f"{quoi} : `rcpt` = `{f.get('rcpt')}` au lieu de `{attendu}`")
        if f.get("user") != masquer(dest):
            fautes.append(f"{quoi} : `user` = `{f.get('user')}` au lieu de `{masquer(dest)}`")
        if "-> <" + masquer(dest) + ">" not in (ev.get("message") or ""):
            fautes.append(f"{quoi} : le message ne masque pas le destinataire : `{(ev.get('message') or '')[:160]}`")
        reste = dict(ev, fields={k: v for k, v in f.items() if k != "rcpt"})
        texte = json.dumps(reste, ensure_ascii=False) + (f.get("rcpt") if boite is None else "")
        for m in sorted(set(MARQUEUR.findall(texte))):
            fautes.append(f"{quoi} : la partie locale `{m}` sort dans l'événement")
        if boite and boite in json.dumps(reste, ensure_ascii=False):
            fautes.append(f"{quoi} : la boîte `{boite}` sort hors du champ `rcpt`")
    return fautes


def juger_reglage(configs, cle_avouee, etat, liste):
    """L'aveu attendu (ou son absence), l'état et la liste retenue dits dans l'enveloppe de config."""
    fautes = []
    aveux = [c for c in configs if (c.get("fields") or {}).get("collect_status") == "fallback"
             and (c.get("fields") or {}).get("reason") == "unreadable-config"]
    cles = sorted({(c["fields"].get("detail") or "").split("=", 1)[0] for c in aveux})
    if cle_avouee is None and aveux:
        fautes.append(f"aveu inattendu sur {cles}")
    if cle_avouee is not None and cles != [cle_avouee]:
        fautes.append(f"aveu attendu sur `{cle_avouee}`, lu sur {cles}")
    etats = [((c.get("fields") or {}).get("filters") or {}).get("destinataire_local") for c in configs
             if (c.get("fields") or {}).get("type") == "collection-reducing"]
    if etats != [etat]:
        fautes.append(f"l'enveloppe de config dit `destinataire_local` = {etats} au lieu de [`{etat}`]")
    listes = [((c.get("fields") or {}).get("filters") or {}).get("domaines_locaux") for c in configs
              if (c.get("fields") or {}).get("type") == "collection-reducing"]
    if listes != [liste]:
        fautes.append(f"l'enveloppe de config dit `domaines_locaux` = {listes} au lieu de [`{liste}`]")
    return fautes


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — la garde REFUSE DE CONCLURE, rien n'a été mesuré.")
    sys.exit(2)


def epoch(ligne):
    return int(datetime.datetime.fromisoformat(ligne[:32]).timestamp())


def partie_locale_restante(message):
    for m in PARTIE_LOCALE_RESTANTE.finditer(message or ""):
        reste = m.group(0)[len(_etiquette(m)):-1]
        if reste != "*":
            return reste
    return None


def _etiquette(m):
    """L'étiquette de champ que le masquage garde devant le morceau `m` (motif `[^ <@]+@`), ou `""`."""
    avant = m.string[m.start() - 1] if m.start() else ""
    if avant in ("<", "@"):
        return ""
    e = ETIQUETTE_DE_CHAMP.search(m.group(0)[:-1])
    return m.group(0)[:e.end()] if e else ""


def originaire(ev):
    return (ev.get("fields") or {}).get("service") == "amavis" and AMAVIS_ORIGINAIRE.search(ev.get("message") or "")


# --- LE JUGE --------------------------------------------------------------------------------------
def juger_fabriquees(evenements):
    fautes, par_ts = [], {}
    for ev in evenements:
        par_ts.setdefault(ev.get("ts"), []).append(ev)
    for n, (ligne, champs, morceaux) in enumerate(FABRIQUEES, 1):
        quoi = f"ligne fabriquée {n} (`{ligne[33:90]}…`)"
        vus = par_ts.pop(epoch(ligne), [])
        if len(vus) != 1:
            fautes.append(f"{quoi} : {len(vus)} événement(s) au lieu d'un — la ligne ne juge rien")
            continue
        ev = vus[0]
        f = ev.get("fields") or {}
        # Le compte d'une entrée ORIGINAIRE est le seul marqueur admis, et dans `sender` seulement.
        reste = dict(ev, fields={k: v for k, v in f.items() if not (k == "sender" and v == COMPTE_LOCAL)})
        texte = json.dumps(reste, ensure_ascii=False)
        for m in sorted(set(MARQUEUR.findall(texte))):
            fautes.append(f"{quoi} : la partie locale `{m}` sort dans l'événement")
        if COMPTE_LOCAL.split("@")[0] in (ev.get("message") or "") + (ev.get("dedup") or ""):
            fautes.append(f"{quoi} : le compte de l'entrée originaire sort dans le message ou la clé")
        for k, v in champs.items():
            if f.get(k) != v:
                fautes.append(f"{quoi} : `{k}` = `{f.get(k)}` au lieu de `{v}`")
        for morceau in morceaux:
            if morceau not in (ev.get("message") or ""):
                fautes.append(f"{quoi} : le message ne porte pas `{morceau}` : `{(ev.get('message') or '')[:200]}`")
    for ts, vus in par_ts.items():
        fautes.append(f"{len(vus)} événement(s) pour une seconde sans ligne fabriquée ({ts})")
    return fautes


def rcpt_local_admis(ev, domaines):
    """`P10.33-f` : un `rcpt` en clair n'est admis que sur `malware`/`banned`, d'un domaine local DÉCLARÉ."""
    v = str((ev.get("fields") or {}).get("rcpt") or "")
    return (bool(domaines) and ev.get("category") in ("malware", "banned") and "@" in v
            and re.fullmatch(r"[a-z0-9.-]+", v.rsplit("@", 1)[1].lower()) is not None
            and v.rsplit("@", 1)[1].lower() in domaines)


def juger_corpus(evenements, domaines=()):
    fautes = []
    for ev in evenements:
        quoi = f"événement `{(ev.get('message') or '')[:110]}`"
        reste = partie_locale_restante(ev.get("message"))
        if reste:
            fautes.append(f"{quoi} : la partie locale `{reste}` subsiste dans le message")
        f = ev.get("fields") or {}
        for k in ("user", "sender", "rcpt"):
            if (k in f and not FORME_MASQUEE.match(str(f[k])) and not (k == "sender" and originaire(ev))
                    and not (k == "rcpt" and rcpt_local_admis(ev, domaines))):
                fautes.append(f"{quoi} : `{k}` = `{f[k]}` n'est pas masqué")
    return fautes


def epreuve_du_juge():
    """Le juge rougit sur des événements faux et se tait sur les bons — sinon la garde refuse de conclure."""
    def ev(n, champs, message=None):
        ligne = FABRIQUEES[n][0]
        m = message if message is not None else " ".join(FABRIQUEES[n][2])
        return {"ts": epoch(ligne), "message": m, "dedup": "d", "fields": dict(champs)}
    bons = [ev(i, dict(c)) for i, (_, c, _) in enumerate(FABRIQUEES)]
    if juger_fabriquees(bons):
        return f"le juge accuse des événements justes : {juger_fabriquees(bons)[:2]}"
    ecarts = {
        "un marqueur dans le message": [dict(bons[0], message=bons[0]["message"] + " marqa")] + bons[1:],
        "un compte en clair": [dict(bons[0], fields=dict(bons[0]["fields"], user="marqa@example.test"))] + bons[1:],
        "l'expéditeur originaire masqué": bons[:7] + [dict(bons[7], fields=dict(bons[7]["fields"], sender="*@example.test"))] + bons[8:],
        "le compte originaire dans le message": bons[:7] + [dict(bons[7], message=bons[7]["message"] + " " + COMPTE_LOCAL)] + bons[8:],
        "l'étiquette mangée": bons[:3] + [dict(bons[3], message="*@example.test")] + bons[4:],
        "un événement manquant": bons[1:],
        "un événement en double": bons + [bons[0]],
    }
    for nom, evs in ecarts.items():
        if not juger_fabriquees(evs):
            return f"le juge des lignes fabriquées ne voit pas « {nom} »"
    if juger_corpus([{"message": "a <*@example.org> sasl_username=*@d x;envelope-from=*@d", "fields": {"user": "*@d", "sender": "", "rcpt": "*"}}]):
        return "le juge des corpus accuse un événement masqué"
    for nom, e in {
        "une partie locale restante": {"message": "to=<jean:*@example.org>", "fields": {}},
        "un `nom=` entre chevrons pris pour une étiquette": {"message": "to=<jean_dupont=*@example.org>", "fields": {}},
        "un `nom=` après `(` pris pour une étiquette": {"message": "imap(a_b=*@example.org)", "fields": {}},
        "un `user` en clair": {"message": "x", "fields": {"user": "jean@example.org"}},
        "un `sender` en clair hors entrée originaire": {"message": "x", "fields": {"sender": "jean@example.org", "service": "amavis"}},
        "un `rcpt` sans arobase en clair": {"message": "x", "fields": {"rcpt": "jean"}},
    }.items():
        if not juger_corpus([e]):
            return f"le juge des corpus ne voit pas « {nom} »"
    # P10.33-f — le juge du destinataire local, dans les deux positions.
    local = {"category": "malware", "message": "x", "fields": {"rcpt": "b@example.test"}}
    if juger_corpus([local], {"example.test"}):
        return "le juge des corpus accuse un destinataire local admis"
    for nom, (e, dom) in {
        "un destinataire local en clair sans réglage": (local, ()),
        "un destinataire externe en clair": (dict(local, fields={"rcpt": "b@example.net"}), {"example.test"}),
        "un destinataire local en clair hors malware/banned": (dict(local, category="mailflow"), {"example.test"}),
        "un sous-domaine pris pour le domaine local": (dict(local, fields={"rcpt": "b@sous.example.test"}), {"example.test"}),
    }.items():
        if not juger_corpus([e], dom):
            return f"le juge des corpus ne voit pas « {nom} »"
    def dev(ligne, cat, rcpt, user=None, message=None):
        dest = ligne.split(" -> <", 1)[1].split(">", 1)[0]
        return {"ts": epoch(ligne), "category": cat, "dedup": "d",
                "message": message if message is not None else "<*@example.net> -> <" + masquer(dest) + ">",
                "fields": {"rcpt": rcpt, "user": user if user is not None else masquer(dest)}}
    for actif in (False, True):
        bons = [dev(l, c, clair if actif else masquer(l.split(" -> <", 1)[1].split(">", 1)[0]))
                for l, c, clair, _ in DESTINATAIRES]
        if juger_destinataires(bons, actif):
            return f"le juge du destinataire local accuse des événements justes : {juger_destinataires(bons, actif)[:2]}"
        inverses = [dev(l, c, clair if not actif else masquer(l.split(" -> <", 1)[1].split(">", 1)[0]))
                    for l, c, clair, _ in DESTINATAIRES]
        if not juger_destinataires(inverses, actif):
            return f"le juge du destinataire local ne voit pas la position inversée (actif={actif})"
    bons = [dev(l, c, clair) for l, c, clair, _ in DESTINATAIRES]
    for nom, evs in {
        "la boîte dans le message": [dict(bons[0], message=bons[0]["message"] + " boitevirus")] + bons[1:],
        "la boîte dans `user`": [dict(bons[0], fields=dict(bons[0]["fields"], user="boitevirus@example.test"))] + bons[1:],
        "le domaine externe en clair": bons[:2] + [dict(bons[2], fields=dict(bons[2]["fields"], rcpt="marqexterne@example.net"))] + bons[3:],
        "le CLEAN local en clair": bons[:4] + [dict(bons[4], fields=dict(bons[4]["fields"], rcpt="marqclean@example.test"))] + bons[5:],
        "une catégorie fausse": [dict(bons[0], category="mailflow")] + bons[1:],
    }.items():
        if not juger_destinataires(evs, True):
            return f"le juge du destinataire local ne voit pas « {nom} »"
    cfg = [{"fields": {"type": "collection-reducing", "filters": {"destinataire_local": "masque",
                                                                   "domaines_locaux": "example.test"}}}]
    aveu = [{"fields": {"collect_status": "fallback", "reason": "unreadable-config", "detail": LISTE_LOCALE + '="" x'}}]
    if juger_reglage(cfg, None, "masque", "example.test") or juger_reglage(cfg + aveu, LISTE_LOCALE, "masque",
                                                                          "example.test"):
        return "le juge du réglage accuse un état juste"
    if not juger_reglage(cfg + aveu, None, "masque", "example.test") \
            or not juger_reglage(cfg, LISTE_LOCALE, "masque", "example.test") \
            or not juger_reglage(cfg, None, "demasque", "example.test") \
            or not juger_reglage(cfg, None, "masque", "example.test x_y"):
        return "le juge du réglage ne voit pas un aveu manquant, en trop, un état ou une liste retenue faux"
    return None


# --- LA RÈGLE QUI FONDE L'EXCEPTION ----------------------------------------------------------------
def la_regle_fonde_l_exception():
    try:
        requete = json.load(open(REGLE, encoding="utf-8"))["query"]
    except (OSError, ValueError, KeyError) as e:
        refus(f"règle `{os.path.relpath(REGLE, RACINE)}` illisible ({e})")
    etapes = [x.strip() for x in requete.split("|")]
    if "service=amavis" in etapes[0].split() and any(re.fullmatch(r"stats count by sender", e) for e in etapes[1:]):
        return []
    return [f"la règle `ex-mail-mass-outbound` ne compte plus `sender` sur `service=amavis` (`{requete}`) : "
            "l'expéditeur d'une entrée originaire n'a plus de raison de sortir en clair"]


# --- LE CAPTEUR -----------------------------------------------------------------------------------
def implementations_awk():
    trouvees, chemins = [], set()
    for nom in AWK_EXERCES:
        chemin = shutil.which(nom)
        if chemin and os.path.realpath(chemin) not in chemins:
            chemins.add(os.path.realpath(chemin))
            trouvees.append((nom, chemin))
    return trouvees


def lignes_des_corpus():
    lignes = []
    for nom in sorted(os.listdir(os.path.join(RACINE, "collectors"))):
        if not (nom.startswith("mail-") and nom.endswith(".corpus")) or nom in CORPUS_CLAMAV:
            continue
        for texte in open(os.path.join(RACINE, "collectors", nom), encoding="utf-8").read().split("\n"):
            if texte and not texte.startswith("#"):
                lignes.append(texte.split("\t")[-1])
    if len(lignes) < 100:
        refus(f"{len(lignes)} lignes de corpus mail lues, moins que le plancher de 100")
    return lignes


def jouer(chemin_awk, lignes, reglages=None, configs=None):
    with tempfile.TemporaryDirectory(prefix="garde-mail-masque-") as bac:
        rep = {d: os.path.join(bac, d) for d in ("bin", "spool", "state")}
        for d in rep.values():
            os.makedirs(d)
        os.symlink(chemin_awk, os.path.join(rep["bin"], "awk"))
        journal = os.path.join(bac, "mail.log")
        with open(journal, "w", encoding="utf-8") as fh:
            fh.write("".join(l + "\n" for l in lignes))
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PLUME_", "LC_", "LANG"))}
        env.update(PATH=rep["bin"] + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
                   PLUME_LIB=LIB, PLUME_SPOOL=rep["spool"], PLUME_STATE=rep["state"], PLUME_MAIL_SRC="file",
                   PLUME_MAIL_LOG=journal, PLUME_MAIL_MAX=str(len(lignes) + 10),
                   PLUME_MAIL_CLAMAV_LOG="", PLUME_MAIL_FRESHCLAM_LOG="", LC_ALL="C.UTF-8")
        env.update(reglages or {})
        # Le répertoire courant est PIÉGÉ : un motif développé par le shell y rend un domaine lisible. Le piège
        # est d'abord éprouvé (un `sh` qui ne développerait pas `*` ici rendrait le témoin vacant).
        courant = os.path.join(bac, "repertoire-courant-piege")
        os.makedirs(courant)
        open(os.path.join(courant, PIEGE_DU_REPERTOIRE_COURANT), "w").close()
        t = subprocess.run(["sh", "-c", "printf '%s' *"], cwd=courant, capture_output=True, text=True, timeout=30)
        if t.stdout != PIEGE_DU_REPERTOIRE_COURANT:
            refus(f"le répertoire courant piégé ne développe pas `*` (`{t.stdout[:80]}`) : le témoin de `set -f` "
                  "serait vacant")
        r = subprocess.run(["sh", CAPTEUR], env=env, cwd=courant, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            refus(f"le capteur a échoué sous `{chemin_awk}` (rc={r.returncode}) : {r.stderr.strip()[:300]}")
        evenements = []
        for nom in sorted(os.listdir(rep["spool"])):
            if nom.startswith(".") or not nom.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(rep["spool"], nom), encoding="utf-8"))
            except (OSError, ValueError) as e:
                return None, f"enveloppe `{nom}` illisible comme JSON ({e})"
            evenements += [ev for ev in doc.get("events") or [] if ev.get("category") != "config"]
            if configs is not None:
                configs += [ev for ev in doc.get("events") or [] if ev.get("category") == "config"]
        return evenements, None


def main():
    for f in (CAPTEUR, LIB):
        if not os.path.exists(f):
            refus(f"`{os.path.relpath(f, RACINE)}` introuvable")
    faute = epreuve_du_juge()
    if faute:
        refus(f"instrument INVALIDE — {faute}")
    corpus = lignes_des_corpus()
    awks = implementations_awk()
    if not awks:
        refus(f"aucune implémentation d'awk parmi {AWK_EXERCES}")
    total = 0
    for f in la_regle_fonde_l_exception():
        print(f"::error file=config.d/rules/catalog/ex-mail-mass-outbound.json::{ETIQUETTE} : {f}")
        total += 1
    vus_corpus = 0
    vus_locaux = 0
    for nom, chemin in awks:
        fautes = []
        ev, ko = jouer(chemin, [l for l, _, _ in FABRIQUEES])
        fautes += [ko] if ko else juger_fabriquees(ev)
        ev, ko = jouer(chemin, corpus)
        if ko:
            fautes.append(ko)
        else:
            if not ev:
                refus(f"aucun événement émis pour les {len(corpus)} lignes de corpus sous `{nom}`")
            vus_corpus = len(ev)
            fautes += juger_corpus(ev)
        for f in fautes:
            print(f"::error file=collectors/mail.sh::{ETIQUETTE} ({nom}) : {f}")
        total += len(fautes)
        # P10.33-f — chaque réglage de REGLAGES_LOCAUX, puis le corpus réglage actif.
        fautes = []
        lignes = [l for l, _, _ in FABRIQUEES] + [l for l, _, _, _ in DESTINATAIRES]
        for quoi, reglages, actif, cle, etat, liste in REGLAGES_LOCAUX:
            configs = []
            ev, ko = jouer(chemin, lignes, reglages, configs)
            if ko:
                fautes.append(f"{quoi} : {ko}")
                continue
            fabriquees = [e for e in ev if e.get("ts") < epoch(DESTINATAIRES[0][0])]
            fautes += [f"{quoi} : {f}" for f in juger_fabriquees(fabriquees) + juger_destinataires(ev, actif)
                       + juger_reglage(configs, cle, etat, liste)]
        ev, ko = jouer(chemin, corpus, {REGLAGE_LOCAL: "1", LISTE_LOCALE: "example.test"})
        if ko:
            fautes.append(f"corpus réglage actif : {ko}")
        else:
            fautes += [f"corpus réglage actif : {f}" for f in juger_corpus(ev, {"example.test"})]
            clairs = sum(1 for e in ev if rcpt_local_admis(e, {"example.test"}) and not FORME_MASQUEE.match(
                str((e.get("fields") or {}).get("rcpt"))))
            vus_locaux = clairs
            if clairs == 0:
                fautes.append("corpus réglage actif : aucun destinataire local démasqué — le réglage ne mord pas")
        for f in fautes:
            print(f"::error file=collectors/mail.sh::{ETIQUETTE_LOCAL} ({nom}) : {f}")
        total += len(fautes)
    exerces = ", ".join(n for n, _ in awks)
    absents = ", ".join(n for n in AWK_EXERCES if n not in {n for n, _ in awks})
    if total:
        print(f"{ETIQUETTE} : {total} défaut(s) (awk exercés : {exerces}).")
        sys.exit(1)
    print(f"{ETIQUETTE} : le capteur mail LIVRÉ masque chaque partie locale qu'il émet — {len(FABRIQUEES)} lignes "
          f"fabriquées (une par famille, marqueurs absents de l'événement, champs masqués, étiquettes `clé=` "
          f"gardées, expéditeur d'une entrée originaire en clair dans `sender` seul, adossé à "
          f"`ex-mail-mass-outbound`) et {vus_corpus} événements des {len(corpus)} lignes de corpus livrées sans "
          f"partie locale restante. {ETIQUETTE_LOCAL} : destinataire local d'un INFECTED/BANNED en clair SEULEMENT réglage à 1 "
          f"avec liste ({len(REGLAGES_LOCAUX)} réglages, {len(DESTINATAIRES)} entrées, aveu sans liste ou valeur "
          f"illisible ; {vus_locaux} démasqué(s) dans le corpus réglage actif). Awk exercés : {exerces}" + (f" ; NON EXERCÉS (absents) : {absents}." if absents else "."))
    sys.exit(0)


if __name__ == "__main__":
    main()
