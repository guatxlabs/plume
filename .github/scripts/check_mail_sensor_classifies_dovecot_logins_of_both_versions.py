#!/usr/bin/env python3
"""Le capteur mail classe les connexions Dovecot 2.3 ET 2.4, lit l'adresse source ENTIÈRE, et ne prend jamais un texte du client pour un verdict — garde de CI (`P10.22-j`, `P10.22-s`, `P10.22-v`, `P10.23-f`, `P10.23-g`, `P10.23-h`, `P10.23-i`, `P10.23-w`, `P10.23-y`, `P10.24-h`, `P10.24-i`, `P10.24-j`).

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
`P10.23-f` — mesuré le 2026-09-24 : les bras postscreen et rejet lisaient encore la ligne entière. Un
`helo=<postscreen PREGREET>` faisait d'un rejet smtpd un blocage postscreen (service compris) ; une
commande HTTP `GET /NOQUEUE: reject` au port de soumission devenait un rejet ; un texte du client
dans un message Dovecot devenait un blocage ; le `helo` du rejet de postscreen lui-même en
choisissait la catégorie. Six lignes sur vingt-trois classées faux, sous gawk et mawk.
`P10.23-g` — même mesure : `DENYLISTED` (la liste de refus quand `respectful_logging` vaut `yes`, son
défaut dès `compatibility_level` 3.6) ne produisait aucun événement ; seul `BLACKLISTED` était lu.
`P10.23-w` (SÉCURITÉ) — mesuré le 2026-09-24 sous gawk, mawk 1.3.4 20200120 et mawk 1.3.4 20250131 :
les bras amavis cherchaient `amavis[pid]:` et `Passed|Blocked` partout dans la ligne. Une commande
HTTP `GET /amavis[1]: Blocked INFECTED (Eicar-Signature)` envoyée sans authentification au port de
soumission devenait un événement `malware` de sévérité quatre (virus au choix, adresse du client) ;
`… virus scanners failed` une panne d'antivirus ; un `ID` IMAP un blocage de pièce jointe ; une ligne
amavis de niveau 1 (`p.path`) recopiant un nom de pièce jointe un malware. Dans l'entrée amavis, le
nom d'une pièce jointe bannie choisissait l'adresse source et le destinataire, un Message-ID
l'identifiant (donc la clé de dédoublonnage : deux lignes, un passage propre puis un malware,
portaient la MÊME clé), le score et la taille ; l'adresse du démon clamd devenait l'adresse source
d'une panne ; `[<e>]`, lue dans les en-têtes `Received:`, l'adresse relais d'un message local.
`P10.23-y` — même mesure : les coupures postscreen `COMMAND LENGTH LIMIT`, `DATA`/`BDAT without
valid RCPT`, et les rejets smtpd sous identifiant de file hors de l'étape RCPT ne produisaient rien.
Mesurés le 2026-09-29 sur le capteur d'avant, sous gawk 5.4.1, mawk 1.3.4 20200120 et 20250131 :
`P10.23-h` — l'échec SASL de smtpd porte `, sasl_username=<nom tenté>` depuis le 20231006 (HISTORY ;
`smtpd_sasl_glue.c` de 3.9.0, et reporté dans 3.8.3, 3.7.8, 3.6.12, 3.5.23 — absent de 3.8.2, 3.7.7,
3.6.11) : le capteur ne le lisait pas, et une pulvérisation de mots de passe sur la soumission ne se
comptait pas par compte. Le corpus disait ce champ « publié à partir de 3.9 » : c'était FAUX.
`P10.23-i` — une ligne CLASSÉE (auth, postscreen, rejet) dont l'adresse ne se valide pas était jetée
sans un mot ; et derrière un client `unknown[unknown]` (`smtpd_peer.c`), le capteur prenait le premier
crochet « qui ressemble à une adresse » : un `helo=<[198.51.100.9]>` écrit par le client devenait
l'adresse source du rejet.
`P10.24-h` — la clé de repli `mail-<seconde>-<adresse>-<action>` servait à TOUT événement sans clé
propre : deux échecs de la même adresse dans la même seconde, même sur deux comptes, portaient la
même clé, et l'ingestion (`INSERT OR IGNORE`) écartait le second.
`P10.24-i` — une entrée amavis coupée à 980 octets était émise champs tus, sans le dire.
`P10.24-j` — `Passed …` et `Blocked …` d'un même message (les deux blocs de `$log_short_templ`,
développés ensemble : amavis `lib/Amavis.pm`, commit 7d473b22) portaient la même clé `mail-<id>`.

CE QUE LA GARDE FAIT
--------------------
Elle lit trois corpus — `collectors/mail-connexions-dovecot.corpus` (connexions Dovecot 2.3 et 2.4),
`collectors/mail-adresses-et-texte-du-client.corpus` (adresses, lignes Postfix, textes du client) et
`collectors/mail-amavis.corpus` (verdicts et pannes d'amavis, mots d'amavis écrits par le client) —
où chaque ligne porte son verdict attendu et la PROVENANCE de sa forme, écrit ces lignes dans un
journal fabriqué, exécute le capteur TEL QU'IL EST LIVRÉ en mode fichier (`PLUME_MAIL_SRC=file`)
dans un bac — spool, état et journal à lui — puis relit l'enveloppe publiée et juge CHAQUE ligne :
  * tout verdict autre que `aucun` et `sans-adresse` -> exactement un événement de la catégorie, de
    l'action et de la SÉVÉRITÉ attendues, avec le `user`, le `src_ip`, le `service` et la CLÉ DE
    DÉDOUBLONNAGE attendus — la clé de repli étant recalculée ici, indépendamment du capteur
    (`empreinte`) ; sur une ligne du corpus amavis, chaque champ amavis attendu (`verdict`, `virus`,
    `sender`, `rcpt`, `score`, `size`, `truncated`), et aucun champ amavis non attendu ;
  * `aucun`  -> aucun événement ; `sans-adresse` -> aucun événement, et COMPTÉE : le passage publie
    un aveu `collect_status=partial` / `reason=unreadable-address`, de sévérité 2, de la source `mail`,
    dont le nombre et la ventilation (auth, postscreen, rejet — chacune exercée) sont ceux des lignes
    `sans-adresse` (aucun aveu quand il n'y en a pas) ;
  * deux événements du passage ne portent jamais la même clé (l'ingestion écarterait le second) ;
  * et aucun événement dont le message n'est pas une ligne d'un corpus (rien d'inventé).
Deux passages de plus, sous chaque awk (`P10.23-i`) : UNE seule ligne `sans-adresse` — l'aveu part dès
une ligne, et sous la même clé qu'au passage entier, au seau horaire près (la clé porte la source, pas
le nombre) ; puis `PLUME_MAIL_SKIP_IP` posé sur l'adresse de lignes classées du corpus — elles ne sont
ni émises ni avouées, une ligne d'une autre adresse l'est.
Le capteur est joué sous `LC_ALL=C.UTF-8`, la locale où gawk lit des caractères et non des octets :
une empreinte calculée par caractère y diffère de celle d'ici sur un nom hors ASCII.
Elle exécute aussi, isolées du capteur livré, ses fonctions d'adresse (`est_ipv4`, `est_ipv6`,
`adresse`) sur une table de valeurs valides et invalides.
Tout est joué sous CHAQUE implémentation d'awk présente parmi `gawk` et `mawk` (l'hôte Debian/Ubuntu
livre `mawk` par défaut ; mawk 1.3.4 20200120, celui de Debian 12 et d'Ubuntu 22.04, ne connaît pas
les intervalles `{n,m}` et ne double pas un antislash écrit "\\\\") : la classification est un
programme awk, et un motif qu'une implémentation lit autrement est un capteur qui ne classe pas
pareil selon l'hôte.

LES CORPUS SE VALIDENT AVANT DE SERVIR
--------------------------------------
Un corpus qui perd sa matière rend un vert vide. Avant toute exécution : cinq colonnes (six, champs amavis
compris, pour le corpus amavis), un verdict et une provenance des vocabulaires fermés, un horodatage ISO et une étiquette syslog reconnue en
tête, une provenance de la famille de l'étiquette ; aucune ligne « Login aborted » déclarée
`succes`, aucune ligne `client-postfix` déclarée `succes` ou `echec`, aucun `postscreen` hors d'une
ligne postscreen, aucun `rejet` hors d'une ligne smtpd ou postscreen, aucun verdict amavis hors
d'une ligne `amavis[pid]:`, aucune valeur attendue marquée `FORGED` (un corpus ne peut pas
légitimer le défaut qu'il garde) ; sur une ligne amavis, l'adresse attendue figure en
`}, [<banque> ][LOCAL ][<adresse>]:<port> ` (la forme d'amavis), le `user` est le premier
destinataire ` -> <…>,`, chaque champ attendu figure à sa place dans la ligne, `truncated=1` est
attendu sur une entrée coupée et sur elle seule, et la clé est `mail-<id>-<Passed|Blocked>-<catégorie>`
d'un `, mail_id: <id>` de la ligne ou la clé de repli ; le `user`
attendu est celui du message Dovecot, et `-` sur toute ligne Postfix SAUF l'échec SASL de smtpd, où
c'est le `, sasl_username=` UNIQUE de la ligne (`(unavailable)` rendu vide) ; le `src_ip` attendu est une adresse sous sa forme rendue (jamais mappée) et figure
dans la ligne là où le serveur l'écrit (`rip=` Dovecot, PREMIER crochet du message Postfix) ; une
ligne `sans-adresse` est une ligne smtpd ou postscreen dont le premier crochet n'est pas une adresse,
ou une connexion Dovecot CLASSÉE dont le dernier `rip=` n'en est pas une ; chaque entrée amavis coupée
suit une entrée complète lue jusqu'au bout, et une entrée complète suit une entrée coupée (`coupee` est
une globale awk : sans ce voisinage, un témoin d'entrée coupée ne mordrait que par l'ordre du corpus) ;
toute adresse, IPv4 ou
IPv6, est de documentation (RFC 5737, RFC 3849) ou de bouclage ; tout utilisateur Dovecot est vide,
sous `example.test`, ou sur une ligne fabriquée. Chaque corpus a son PLANCHER, écrit exigence par
exigence ci-dessous. Cette validation est elle-même éprouvée sur des lignes FABRIQUÉES : trois lignes
conformes passent (un rejet Postfix, un échec SASL, une entrée amavis), et chaque écart — sur la forme
Postfix, sur le nom SASL, sur la forme d'amavis — est refusé, un par un.

LE JUGE SE VALIDE AUSSI
-----------------------
Avant de juger le capteur, le juge est éprouvé sur des événements FABRIQUÉS : le résultat exact ne
doit rien accuser ; un succès manquant, un succès rendu en échec, un rejet rendu en échec, un
événement pour une ligne `aucun`, un `user` faux, un `src_ip` faux, un `service` faux, une
sévérité fausse, un virus faux, un score faux, une clé de dédoublonnage fausse, la clé de repli
d'avant (sans empreinte), deux événements sous la même clé, un champ amavis non attendu et un
événement inventé doivent CHACUN être accusés ; l'aveu des lignes sans adresse est jugé de même
(absent, au mauvais compte, sous `unavailable`, d'une autre sévérité ou d'une autre source, ou émis quand
rien n'est à avouer : accusé), sa clé aussi (le seau horaire seul peut changer). Le voisinage des
entrées coupées est éprouvé sur des entrées fabriquées.

CE QUE LA GARDE NE TIENT PAS, DIT FRANCHEMENT
---------------------------------------------
Elle éprouve la CLASSIFICATION du capteur livré, pas ce qui tourne sur l'hôte : un capteur corrigé
ici et jamais installé ne classe rien (famille de `P10.22-i`). Les formes `sources-*` sont dérivées
des sources, pas relevées ; seules les lignes `mesuree-*` l'ont été, et aucune ligne Postfix ne
l'est, et aucune ligne amavis (`sources-amavis` : branche master d'amavis, NON MESURÉE). Un champ
amavis que le client recopie est TU, jamais pris : le client peut donc taire l'adresse, le
destinataire ou l'identifiant de SON message (il retombe alors sur la clé de repli, qui porte
l'empreinte de la ligne), pas les choisir. Le nom SASL est par nature celui que le client a TENTÉ :
la garde tient qu'il n'est lu qu'à la place où smtpd l'écrit, pas qu'il désigne un compte existant.
Deux lignes identiques à l'octet (même microseconde) donnent une seule clé : sans compteur, un rejeu et
une vraie répétition ne se distinguent pas, et un compteur casserait l'absorption du rejeu.
L'empreinte n'est pas cryptographique (31 bits, polynôme connu) : une collision voulue ne toucherait
qu'un événement de la même seconde, de la même adresse (ou sans adresse) et de la même action, et
supposerait de prévoir les DEUX lignes à l'octet, microseconde comprise. Un gabarit
`$log_templ` réécrit par l'exploitant n'est pas couvert ; la suite d'une entrée coupée n'est pas
recollée (l'entrée le DIT, `truncated=1`). Qu'un échec SASL de `unknown[unknown]` (non classé : la
forme ancrée exige une adresse) échappe au compte `sans-adresse` n'a pas de témoin. Les lignes qui
exercent les catégories `auth` (Dovecot sans `rip=`) et `postscreen` (client `[unknown]`) de l'aveu
sont FABRIQUÉES : aucune n'est relevée, et aucune source lue ne montre postscreen écrivant un client
illisible. Les unités awk
des capteurs échappent au recensement des définitions d'adresse de `P4.7-j`.
Sortie : 0 tenu · 1 défaut · 2 rien n'a été mesuré (capteur, bibliothèque ou corpus absent, corpus
invalide ou sous son plancher, juge ou validation non discriminants, aucun awk, capteur en échec,
fonction d'adresse introuvable, spool illisible).
"""
import datetime
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
CORPUS_AMAVIS = os.path.join(RACINE, "collectors", "mail-amavis.corpus")
ETIQUETTE = "P10.22-j/s/v, P10.23-f/g/h/i/w/y, P10.24-h/i/j"

# `sans-adresse` (P10.23-i) : aucun événement, comme `aucun`, mais la ligne est COMPTÉE dans l'aveu.
CLASSE_DU_VERDICT = {"succes": ("auth", "success"), "echec": ("auth", "failure"),
                     "rejet": ("reject", "blocked"), "postscreen": ("postscreen", "blocked"),
                     "malware": ("malware", "infected"), "banni": ("banned", "banned"),
                     "flux-passe": ("mailflow", "pass"), "flux-spam": ("mailflow", "spam"),
                     "flux-bloque": ("mailflow", "blocked"), "panne-av": ("av_error", "error"),
                     "aucun": None, "sans-adresse": None}
# P10.23-w — la sévérité fait partie du verdict : le constat est une alerte de sévérité QUATRE.
SEVERITE_DU_VERDICT = {"succes": 1, "echec": 2, "rejet": 2, "postscreen": 2, "malware": 4, "banni": 3,
                       "flux-passe": 1, "flux-spam": 2, "flux-bloque": 2, "panne-av": 3}
VERDICTS_AMAVIS = ("malware", "banni", "flux-passe", "flux-spam", "flux-bloque", "panne-av")
# Les champs qu'une entrée amavis porte, et que le juge compare un à un (`dedup` à part). `truncated`
# (P10.24-i) n'est porté que par une entrée COUPÉE.
CHAMPS_AMAVIS = ("verdict", "virus", "sender", "rcpt", "score", "size", "truncated")
# P10.24-h — la clé de repli `mail-<epoch>-<src_ip>-<action>-<empreinte de la ligne>`.
REPLI_DE_DEDOUBLONNAGE = "(empreinte)"
BASE_DE_L_EMPREINTE, MODULE_DE_L_EMPREINTE = 257, 2147483629


def empreinte(ligne):
    """L'empreinte que le capteur calcule, écrite ICI une seconde fois — sur les OCTETS UTF-8 de la ligne
    brute, horodatage compris : somme polynomiale modulaire (`collectors/mail.sh`, `empreinte`)."""
    h = 0
    for octet in ligne.encode("utf-8"):
        h = (h * BASE_DE_L_EMPREINTE + octet) % MODULE_DE_L_EMPREINTE
    return h


def cle_de_repli(epoch, ip, action, ligne):
    return f"mail-{epoch}-{ip}-{action}-{empreinte(ligne)}"


# P10.24-j — la clé d'une entrée amavis identifiée : `mail-<id>-<Passed|Blocked>-<catégorie>`.
def cle_amavis(mail_id, verdict):
    return f"mail-{mail_id}-{verdict.replace(' ', '-', 1)}"


# P10.23-h — l'échec SASL de smtpd, ancré comme dans le capteur, et le nom SASL qu'on y lit : `None` si la
# ligne n'est pas un échec SASL de smtpd, `""` si le nom est absent, `(unavailable)` ou pas UNIQUE.
ECHEC_SASL_SMTPD = re.compile(r"^warning: [A-Za-z0-9._-]+\[[0-9A-Fa-f:.]+\](?::\d+)?: SASL [A-Za-z0-9_-]+ "
                              r"authentication failed(.*)$")
REPERE_SASL = ", sasl_username="


def utilisateur_sasl_attendu(message):
    m = ECHEC_SASL_SMTPD.match(message)
    if not m:
        return None
    reste = m.group(1)
    if reste.count(REPERE_SASL) != 1:
        return ""
    nom = reste.split(REPERE_SASL, 1)[1]
    return "" if nom == "(unavailable)" else nom


# P10.23-i — le client d'une ligne Dovecot : le DERNIER `rip=` du message, lu comme le capteur
# (`rip_de_dovecot`) ; et les formes de connexion que le capteur CLASSE (succès, trois formes d'échec).
CONNEXION_DOVECOT_CLASSEE = re.compile(r"^(?:imap|pop3|submission|managesieve)-login: (?:(?:Login|Logged in): "
                                       r"|[^<=]*\(auth failed[,)]|(?:Disconnected: )?Aborted login[ (]|Login aborted: Logged out )")


def rip_de_dovecot(message):
    vus = re.findall(r"[,:] rip=([^, ]*)", message)
    return vus[-1] if vus else ""


def premier_crochet(message):
    """Le contenu du PREMIER `[…]` du message, ou None : c'est là, et là seulement, que Postfix écrit
    son client (`nom[adresse]`, `[adresse]:port`)."""
    o = message.find("[")
    f = message.find("]", o + 1) if o >= 0 else -1
    return message[o + 1:f] if f >= 0 else None
# Chaque corpus : ses verdicts, son nombre de colonnes, et pour chaque provenance le GROUPE
# d'étiquettes qu'elle exige (`dovecot`, `postfix` — smtpd, smtp, postscreen —, `amavis`).
SPEC_DOVECOT = dict(
    nom="mail-connexions-dovecot.corpus", colonnes=5,
    verdicts=("succes", "echec", "aucun"),
    provenances={p: "dovecot" for p in ("mesuree-2.4.1", "sources-2.4.1", "fabriquee-2.4",
                                         "mesuree-2.3.19.1", "enonce-2.3", "sources-2.3.19.1", "fabriquee-2.3")},
)
SPEC_CLIENT = dict(
    nom="mail-adresses-et-texte-du-client.corpus", colonnes=5,
    verdicts=("succes", "echec", "rejet", "postscreen", "sans-adresse", "aucun"),
    provenances={"sources-2.3.19.1": "dovecot", "sources-2.4.1": "dovecot", "fabriquee-2.4": "dovecot",
                 "enonce-P10.22-s": "dovecot", "fabriquee-2.3": "dovecot", "fabriquee-dovecot-sans-rip": "dovecot",
                 "sources-postfix": "postfix", "sources-postfix-sans-sasl-username": "postfix",
                 "fabriquee-postfix": "postfix", "fabriquee-postscreen-sans-adresse": "postfix",
                 "client-postfix": "postfix"},
)
SPEC_AMAVIS = dict(
    nom="mail-amavis.corpus", colonnes=6,
    verdicts=VERDICTS_AMAVIS + ("rejet", "postscreen", "aucun"),
    provenances={"sources-amavis": "amavis", "client-amavis": "amavis", "client-postfix": "postfix",
                 "fabriquee-2.3": "dovecot"},
)
SERVICES_DE_CONNEXION = ("imap", "pop3", "submission", "managesieve")
AWK_EXERCES = ("gawk", "mawk")
PLAGES_DE_DOCUMENTATION = [ipaddress.ip_network(n) for n in
                           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8",
                            "2001:db8::/32", "::1/128")]
HORODATAGE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?[+-]\d\d:\d\d ")
# L'étiquette syslog, TROISIÈME champ : c'est elle, et elle seule, qui dit qui a écrit la ligne.
FAMILLE = re.compile(r"^\S+ \S+ (?:(?P<dovecot>dovecot(?:\[\d+\])?)|(?P<postscreen>postfix(?:/[\w.-]+)*/postscreen\[\d+\])"
                     r"|(?P<smtpd>postfix(?:/[\w.-]+)*/smtpd\[\d+\])|(?P<smtp>postfix(?:/[\w.-]+)*/smtp\[\d+\])"
                     r"|(?P<amavis>amavis\[\d+\])): ")
SERVICE_DE_LA_FAMILLE = {"dovecot": "dovecot", "postscreen": "postscreen", "smtpd": "postfix", "smtp": "postfix",
                         "amavis": "amavis"}
GROUPE_DE_LA_FAMILLE = {"dovecot": "dovecot", "postscreen": "postfix", "smtpd": "postfix", "smtp": "postfix",
                        "amavis": "amavis"}
HORODATAGE_ET_DECALAGE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?([+-]\d\d:\d\d) ")
QUADRUPLET = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])")
SUITE_HEXA = re.compile(r"[0-9A-Fa-f:.]+")
UTILISATEUR = re.compile(r"user=<([^>]*)>")
SERVICE_DOVECOT = re.compile(r"^\S+ \S+ dovecot(?:\[\d+\])?: ([a-z0-9]+)-login: ")
MESSAGE = re.compile(r"^\S+ \S+ \S+ (.*)$")
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


def lire_champs(texte):
    """`(champs, fautes)` : la colonne `champs` du corpus amavis — `-`, ou `clé=valeur` séparés par `;`."""
    if texte == "-":
        return {}, []
    champs, fautes = {}, []
    for morceau in texte.split(";"):
        cle, egal, valeur = morceau.partition("=")
        if not egal or cle not in CHAMPS_AMAVIS + ("dedup",):
            fautes.append(f"champ `{morceau}` hors vocabulaire {list(CHAMPS_AMAVIS) + ['dedup']}")
        elif cle in champs:
            fautes.append(f"champ `{cle}` en double")
        else:
            champs[cle] = valeur
    return champs, fautes


# L'adresse relais d'amavis : `[<a>]:<port>` JUSTE après `{<actions>}, ` et la banque éventuelle.
def _forme_du_relais_amavis(ip):
    return re.compile(r"\}, (?:[\w./-]+ )?(?:LOCAL )?\[" + re.escape(ip) + r"\]:\d+ ")


def valider_amavis(n, verdict, user, ip, champs, ligne):
    """Les attendus d'une ligne `amavis[pid]:` : chaque valeur attendue figure À SA PLACE dans la forme
    d'amavis — une attente qu'aucune position d'amavis ne porte légitimerait un champ lu ailleurs."""
    fautes = []
    if verdict == "aucun":
        return [f"ligne {n} : des champs amavis attendus sur une ligne `aucun`"] if champs else []
    if verdict == "panne-av":
        if ip != "-":
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` sur une panne d'antivirus — une panne n'a pas de client")
        if champs != {"dedup": REPLI_DE_DEDOUBLONNAGE}:
            fautes.append(f"ligne {n} : une panne attend `dedup={REPLI_DE_DEDOUBLONNAGE}` et rien d'autre")
        return fautes
    # P10.24-i — une entrée qui ne finit pas par `, <n> ms` est COUPÉE : `truncated=1` est attendu, et nulle
    # part ailleurs.
    coupee = not re.search(r", \d+ ms$", ligne)
    requis = ({"verdict", "sender", "rcpt", "score", "size", "dedup"} | ({"virus"} if verdict == "malware" else set())
              | ({"truncated"} if coupee else set()))
    if set(champs) != requis:
        fautes.append(f"ligne {n} : champs attendus {sorted(champs)} au lieu de {sorted(requis)}")
        return fautes
    if coupee and champs.get("truncated") != "1":
        fautes.append(f"ligne {n} : une entrée coupée attend `truncated=1`, pas `{champs.get('truncated')}`")
    if not re.match(r"^\S+ \S+ amavis\[\d+\]: \([^ ()]+\) " + re.escape(champs["verdict"]) + r" ", ligne):
        fautes.append(f"ligne {n} : verdict `{champs['verdict']}` absent de la tête du message")
    if verdict == "malware" and f"INFECTED ({champs['virus']}) {{" not in ligne:
        fautes.append(f"ligne {n} : virus `{champs['virus']}` absent de `INFECTED (…) {{`")
    if champs["sender"] and f" <{champs['sender']}> -> " not in ligne:
        fautes.append(f"ligne {n} : expéditeur `{champs['sender']}` absent de ` <…> -> `")
    if champs["rcpt"] and f" -> <{champs['rcpt']}>," not in ligne:
        fautes.append(f"ligne {n} : destinataire `{champs['rcpt']}` absent de ` -> <…>,`")
    if (user if user != "-" else "") != champs["rcpt"]:
        fautes.append(f"ligne {n} : `user` attendu `{user}` ≠ premier destinataire `{champs['rcpt']}`")
    if champs["size"] and f", Hits: {champs['score'] or '-'}, size: {champs['size']}" not in ligne:
        fautes.append(f"ligne {n} : score et taille `{champs['score']}`/`{champs['size']}` absents de `, Hits: …, size: …`")
    if champs["score"] and not champs["size"]:
        fautes.append(f"ligne {n} : un score attendu sans sa taille — les deux se lisent ensemble")
    # P10.24-j — la clé d'une entrée identifiée porte le verdict ET la catégorie : `mail-<id>-Passed-CLEAN`.
    d, suffixe = champs["dedup"], "-" + champs["verdict"].replace(" ", "-", 1)
    if d != REPLI_DE_DEDOUBLONNAGE and not (d.startswith("mail-") and d.endswith(suffixe)
                                            and f", mail_id: {d[5:-len(suffixe)]}, " in ligne):
        fautes.append(f"ligne {n} : clé `{d}` ni `{REPLI_DE_DEDOUBLONNAGE}` ni `mail-<id>{suffixe}` d'un "
                      f"`, mail_id: <id>` de la ligne")
    if ip != "-" and not _forme_du_relais_amavis(ip).search(ligne):
        fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` absent de la forme d'amavis `}}, […][LOCAL ][<adresse>]:<port> `")
    return fautes


def epoch_de_la_ligne(ligne):
    """L'epoch que le capteur calcule (heure à la seconde, moins le décalage), ou None."""
    m = HORODATAGE_ET_DECALAGE.match(ligne)
    return int(datetime.datetime.fromisoformat(m.group(1) + m.group(2)).timestamp()) if m else None


def analyser_ligne(n, texte, spec):
    """Rend `(entrée, fautes)` pour une ligne de corpus — la validation, écrite une fois pour tous."""
    colonnes = texte.split("\t")
    if len(colonnes) != spec["colonnes"]:
        return None, [f"ligne {n} : {len(colonnes)} colonnes au lieu de {spec['colonnes']}"]
    if spec["colonnes"] == 6:
        verdict, user, ip, provenance, texte_des_champs, ligne = colonnes
    else:
        verdict, user, ip, provenance, ligne = colonnes
        texte_des_champs = "-"
    fautes = []
    champs, f_champs = lire_champs(texte_des_champs)
    fautes += [f"ligne {n} : {f}" for f in f_champs]
    if verdict not in spec["verdicts"]:
        fautes.append(f"ligne {n} : verdict `{verdict}` hors vocabulaire {list(spec['verdicts'])}")
    if provenance not in spec["provenances"]:
        fautes.append(f"ligne {n} : provenance `{provenance}` hors vocabulaire")
    if not HORODATAGE.match(ligne):
        fautes.append(f"ligne {n} : pas d'horodatage ISO avec décalage en tête — le capteur l'ignorerait")
    f = FAMILLE.match(ligne)
    famille = f.lastgroup if f else None
    m_ = MESSAGE.match(ligne)
    message = m_.group(1) if m_ else ""
    if famille is None:
        fautes.append(f"ligne {n} : étiquette syslog non reconnue en troisième champ")
    elif provenance in spec["provenances"] and GROUPE_DE_LA_FAMILLE[famille] != spec["provenances"][provenance]:
        fautes.append(f"ligne {n} : provenance `{provenance}` sur une ligne `{famille}`")
    if verdict == "succes" and "Login aborted" in ligne:
        fautes.append(f"ligne {n} : une ligne « Login aborted » déclarée `succes` — le corpus légitimerait le défaut qu'il garde")
    if provenance == "client-postfix" and verdict in ("succes", "echec"):
        fautes.append(f"ligne {n} : un texte du client déclaré `{verdict}` — le corpus légitimerait le défaut qu'il garde")
    # P10.23-f et P10.23-w — la catégorie suit l'ÉTIQUETTE : seul postscreen bloque, seuls smtpd et
    # postscreen rejettent, seul amavis rend un verdict antivirus.
    if famille is not None and ((verdict == "postscreen" and famille != "postscreen")
                                or (verdict == "rejet" and famille not in ("smtpd", "postscreen"))
                                or (verdict in VERDICTS_AMAVIS and famille != "amavis")):
        fautes.append(f"ligne {n} : une ligne `{famille}` déclarée `{verdict}` — le corpus légitimerait le défaut qu'il garde")
    if "FORGED" in user or "FORGED" in ip or any("FORGED" in v for v in champs.values()):
        fautes.append(f"ligne {n} : une valeur attendue porte la marque `FORGED` d'un texte du client")
    if famille != "amavis" and champs:
        fautes.append(f"ligne {n} : des champs amavis attendus sur une ligne `{famille}`")
    attendu_user = "" if user == "-" else user
    if famille == "dovecot":
        u = UTILISATEUR.search(ligne)
        u_ligne = u.group(1) if u else ""
        if attendu_user != u_ligne:
            fautes.append(f"ligne {n} : `user` attendu `{user}` ≠ `user=<{u_ligne}>` de la ligne")
        if u_ligne and not u_ligne.endswith("@example.test") and not provenance.startswith("fabriquee-"):
            fautes.append(f"ligne {n} : utilisateur `{u_ligne}` hors de `example.test`")
    elif famille == "amavis":
        fautes += valider_amavis(n, verdict, user, ip, champs, ligne)
    elif famille == "smtpd" and verdict == "echec" and (sasl := utilisateur_sasl_attendu(message)) is not None:
        # P10.23-h — la SEULE ligne Postfix qui porte un utilisateur : l'échec SASL de smtpd, dont le nom
        # tenté est le `, sasl_username=` UNIQUE de la ligne. Toute autre attente légitimerait un nom lu
        # ailleurs (un `helo=<…>`, la raison).
        if attendu_user != sasl:
            fautes.append(f"ligne {n} : `user` attendu `{user}` ≠ `{sasl or '-'}`, le `, sasl_username=` unique de "
                          "l'échec SASL (`(unavailable)` ou repère recopié : vide)")
        if sasl and not sasl.endswith("@example.test") and not provenance.startswith("fabriquee-"):
            fautes.append(f"ligne {n} : nom SASL `{sasl}` hors de `example.test`")
    elif user != "-":
        fautes.append(f"ligne {n} : `user` attendu `{user}` sur une ligne Postfix — le capteur n'y en lit aucun "
                      "hors de l'échec SASL de smtpd, et l'attendre légitimerait un champ écrit par le client")
    if verdict in ("aucun", "sans-adresse"):
        if ip != "-":
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` sur une ligne `{verdict}`")
        # P10.23-i — une ligne comptée sans adresse est une ligne dont le client n'est PAS une adresse :
        # premier crochet d'une ligne smtpd ou postscreen, dernier `rip=` d'une connexion Dovecot CLASSÉE ;
        # sinon le corpus légitimerait l'abandon d'une ligne attribuable.
        if verdict == "sans-adresse":
            if famille == "dovecot":
                rip = rip_de_dovecot(message)
                if not CONNEXION_DOVECOT_CLASSEE.match(message):
                    fautes.append(f"ligne {n} : `sans-adresse` sur une ligne Dovecot que le capteur ne classe pas — elle ne serait pas comptée")
                elif _adresse_ou_rien(rip) is not None:
                    fautes.append(f"ligne {n} : `sans-adresse` alors que le `rip=` du serveur `{rip}` est une adresse")
            elif famille in ("smtpd", "postscreen"):
                crochet = premier_crochet(message)
                if crochet is None or _adresse_ou_rien(crochet) is not None:
                    fautes.append(f"ligne {n} : `sans-adresse` alors que le premier crochet `[{crochet}]` est une adresse (ou absent)")
            else:
                fautes.append(f"ligne {n} : `sans-adresse` sur une ligne `{famille}` — seules Dovecot, smtpd et postscreen y sont jugées")
    elif ip == "-" and famille == "amavis":
        pass  # amavis : une entrée sans adresse relais lisible (ou une panne) n'a pas d'adresse source
    else:
        a = _adresse_ou_rien(ip)
        if a is None:
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` n'est pas une adresse")
        elif a.version == 6 and a.ipv4_mapped:
            fautes.append(f"ligne {n} : `src_ip` attendu sous la forme mappée `{ip}` — le capteur la rend en IPv4")
        elif famille == "dovecot" and f"rip={ip}," not in ligne and f"rip=::ffff:{ip}," not in ligne:
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` absent des champs `rip=` de la ligne")
        elif famille not in (None, "dovecot", "amavis") and f"[{ip}]" not in ligne:
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` absent des crochets de la ligne")
        elif famille not in (None, "dovecot", "amavis") and premier_crochet(message) != ip:
            # P10.23-i — le client est le PREMIER crochet du message ; plus loin, c'est le client qui écrit.
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` n'est pas le premier crochet du message "
                          f"(`[{premier_crochet(message)}]`) — l'attendre légitimerait un crochet écrit par le client")
    adresses, illisibles = adresses_de_la_ligne(ligne)
    for q in illisibles:
        fautes.append(f"ligne {n} : `{q}` n'est pas une adresse")
    for a in adresses:
        if not de_documentation(a):
            fautes.append(f"ligne {n} : adresse `{a}` hors des plages de documentation — une vraie adresse n'a rien à faire ici")
    s_ = SERVICE_DOVECOT.search(ligne)
    service = "clamav" if verdict == "panne-av" else SERVICE_DE_LA_FAMILLE.get(famille)
    entree = dict(n=n, corpus=spec["nom"], verdict=verdict, user=attendu_user, ip=("" if ip == "-" else ip),
                  provenance=provenance, champs=champs, epoch=epoch_de_la_ligne(ligne),
                  version=("2.4" if "2.4" in provenance else "2.3" if "2.3" in provenance else None),
                  famille=famille, service=service,
                  login=(s_.group(1) if s_ else None), message=message, ligne=ligne)
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


# P10.23-y — les coupures postscreen que l'ancien motif ne lisait pas (`postscreen_smtpd.c`).
FORMES_POSTSCREEN_Y = ("COMMAND LENGTH LIMIT from ", "DATA without valid RCPT from ", "BDAT without valid RCPT from ")

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
    ("P10.22-v : un échec SASL Postfix AVEC `, sasl_username=` (depuis le 20231006 : 3.9.0, 3.8.3, 3.7.8, 3.6.12, 3.5.23)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and ", sasl_username=" in e["ligne"]),
    ("P10.22-v : un échec SASL Postfix SANS `, sasl_username=` (avant le 20231006)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and "sasl_username=" not in e["ligne"]),
    # P10.23-h — le nom SASL lu à sa place, tu dès qu'il est ambigu, jamais pris ailleurs.
    ("P10.23-h : l'utilisateur d'un échec SASL de smtpd, LU en fin de ligne",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and e["user"]
     and e["ligne"].endswith(REPERE_SASL + e["user"])),
    ("P10.23-h : `sasl_username=(unavailable)`, rendu vide",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and not e["user"]
     and e["ligne"].endswith(REPERE_SASL + "(unavailable)")),
    ("P10.23-h : `, sasl_username=` recopié (par le nom tenté ou la raison), utilisateur TU",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and not e["user"] and e["ligne"].count(REPERE_SASL) > 1),
    ("P10.23-h : un nom SASL hors ASCII, lu octet pour octet",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and any(ord(c) > 127 for c in e["user"])),
    ("P10.23-h : un nom SASL portant une espace et une virgule, lu jusqu'en fin de ligne",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "echec" and " " in e["user"] and "," in e["user"]
     and e["ligne"].endswith(REPERE_SASL + e["user"])),
    ("P10.23-h : `, sasl_username=` écrit par le client dans un rejet, jamais un utilisateur",
     lambda e: _client(e, REPERE_SASL) and e["famille"] == "smtpd" and e["verdict"] == "rejet" and not e["user"]),
    # P10.23-i — la ligne classée dont le client n'est pas une adresse : comptée, jamais attribuée.
    ("P10.23-i : un rejet d'un client `unknown[unknown]`, compté sans adresse",
     lambda e: e["verdict"] == "sans-adresse" and "from unknown[unknown]: " in e["message"]),
    ("P10.23-i : `unknown[unknown]` suivi d'un crochet écrit par le client, compté et jamais pris",
     lambda e: e["verdict"] == "sans-adresse" and _client(e, "helo=<[")),
    # La ventilation de l'aveu, exercée sous ses TROIS catégories (le rejet l'est par les deux ci-dessus).
    ("P10.23-i : un échec Dovecot sans `rip=` valide, compté sans adresse sous `auth`",
     lambda e: e["verdict"] == "sans-adresse" and e["famille"] == "dovecot" and categorie_sans_adresse(e) == "auth"),
    ("P10.23-i : un blocage postscreen dont le client n'est pas une adresse, compté sous `postscreen`",
     lambda e: e["verdict"] == "sans-adresse" and e["famille"] == "postscreen" and categorie_sans_adresse(e) == "postscreen"),
    ("P10.23-i : une ligne classée à l'adresse épargnée (`PLUME_MAIL_SKIP_IP`, passage d'épargne)",
     lambda e: e["ip"] == ADRESSE_EPARGNEE and _classee_hors_amavis(e)),
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
] + [
    # P10.23-f et P10.23-g — chaque forme bloquante de postscreen, lue en tête de son message (deux noms
    # pour la liste de refus) ; chaque forme non bloquante, qui n'est rien.
    (f"P10.23-{'g' if forme.endswith('LISTED [') else 'y' if forme in FORMES_POSTSCREEN_Y else 'f'} : "
     f"postscreen `{forme.strip()}` en tête du message, bloquant",
     lambda e, forme=forme: e["famille"] == "postscreen" and e["verdict"] == "postscreen" and e["message"].startswith(forme))
    for forme in ("PREGREET ", "DNSBL rank ", "BLACKLISTED [", "DENYLISTED [", "COMMAND PIPELINING from ",
                  "COMMAND TIME LIMIT from ", "COMMAND COUNT LIMIT from ", "BARE NEWLINE from ", "NON-SMTP COMMAND from ")
    + FORMES_POSTSCREEN_Y
] + [
    (f"P10.23-f : postscreen `{forme.strip()}`, non bloquant, n'est rien",
     lambda e, forme=forme: e["famille"] == "postscreen" and e["verdict"] == "aucun" and e["message"].startswith(forme))
    for forme in ("HANGUP after ", "CONNECT from ", "PASS NEW ", "ALLOWLISTED [", "WHITELISTED [")
] + [
    ("P10.23-f : le rejet de postscreen lui-même",
     lambda e: e["famille"] == "postscreen" and e["verdict"] == "rejet" and e["message"].startswith("NOQUEUE: reject: ")),
    ("P10.23-f : un rejet smtpd sous identifiant de file (`<file>: reject: RCPT`)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "rejet" and re.match(r"[0-9A-Z]+: reject: RCPT from ", e["message"])
     and not e["message"].startswith("NOQUEUE")),
    ("P10.23-f : un rejet smtpd à la connexion (`NOQUEUE: reject: CONNECT`)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "rejet" and e["message"].startswith("NOQUEUE: reject: CONNECT from ")),
    ("P10.23-f : un rejet de milter à l'étape RCPT (parité avec l'ancien motif)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "rejet" and "milter-reject: RCPT from " in e["message"]),
    ("P10.23-f : `postscreen PREGREET` écrit par le client dans un rejet smtpd",
     lambda e: _client(e, "postscreen PREGREET") and e["famille"] == "smtpd" and e["verdict"] == "rejet"),
    # Les deux suivantes portent la forme COMPLÈTE, deux-points compris : c'est elle qui distingue un
    # motif ancré en tête du message d'un motif cherché dans tout le message sous la bonne étiquette.
    ("P10.23-f : `NOQUEUE: reject: RCPT from` écrit par le client hors d'un rejet",
     lambda e: _client(e, "NOQUEUE: reject: RCPT from") and e["famille"] == "smtpd" and e["verdict"] == "aucun"),
    ("P10.23-f : `BLACKLISTED` écrit par le client dans une ligne smtpd",
     lambda e: _client(e, "BLACKLISTED") and e["famille"] == "smtpd" and e["verdict"] == "aucun"),
    ("P10.23-g : `DENYLISTED` écrit par le client dans une ligne smtpd",
     lambda e: _client(e, "DENYLISTED") and e["famille"] == "smtpd" and e["verdict"] == "aucun"),
    ("P10.23-f : un mot de postscreen écrit par le client dans le `helo` du rejet de postscreen",
     lambda e: _client(e, "helo=<DNSBL rank") and re.search(r"helo=<DNSBL rank \d+ for \[", e["ligne"])
     and e["famille"] == "postscreen" and e["verdict"] == "rejet"),
    ("P10.23-f : un mot de postscreen et de rejet dans un message Dovecot",
     lambda e: e["famille"] == "dovecot" and e["verdict"] == "aucun" and "PREGREET" in e["ligne"] and "NOQUEUE: reject" in e["ligne"]),
] + [
    # P10.23-y — sous identifiant de file, hors de l'étape RCPT.
    (f"P10.23-y : un {action} smtpd sous identifiant de file à l'étape `{etape}`",
     lambda e, action=action, etape=etape: e["famille"] == "smtpd" and e["verdict"] == "rejet"
     and re.match(r"[0-9A-Z]+: " + action + ": " + etape + " from ", e["message"]) and not e["message"].startswith("NOQUEUE"))
    for action, etape in (("reject", "DATA"), ("reject", "END-OF-MESSAGE"), ("milter-reject", "END-OF-MESSAGE"))
] + [
    ("P10.23-y : un rejet de milter hors de l'étape RCPT sans file (`NOQUEUE: milter-reject: CONNECT`)",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "rejet" and e["message"].startswith("NOQUEUE: milter-reject: CONNECT from ")),
    ("P10.23-y : un rejet sous identifiant de file écrit par le client hors d'un rejet",
     lambda e: _client(e, ": reject: DATA from") and e["famille"] == "smtpd" and e["verdict"] == "aucun"),
    ("P10.23-y : `DATA without valid RCPT` écrit par le client dans une ligne smtpd",
     lambda e: _client(e, "DATA without valid RCPT") and e["famille"] == "smtpd" and e["verdict"] == "aucun"),
    ("P10.23-y : `COMMAND LENGTH LIMIT` écrit par le client dans le `helo` du rejet de postscreen",
     lambda e: _client(e, "helo=<COMMAND LENGTH LIMIT from [") and e["famille"] == "postscreen" and e["verdict"] == "rejet"),
]


def _amavis(e, verdict, *textes):
    return e["famille"] == "amavis" and e["verdict"] == verdict and all(t in e["ligne"] for t in textes)


def _tete_amavis(e):
    m = re.match(r"\([^ ()]+\) (Passed|Blocked) ([A-Z][A-Z0-9-]*)", e["message"])
    return (m.group(1), re.sub(r"-[0-9]+$", "-", m.group(2))) if m else (None, None)


# P10.23-w — le plancher du corpus amavis, EXIGENCE PAR EXIGENCE : chaque ligne que le capteur d'avant
# classait faux, chaque catégorie de `$log_short_templ`, chaque forme de la tête et du relais.
CATEGORIES_AMAVIS = ("CLEAN", "SPAMMY", "SPAM", "BANNED", "INFECTED", "BAD-HEADER-", "UNCHECKED",
                     "UNCHECKED-ENCRYPTED", "OVERSIZED", "MTA-BLOCKED", "OTHER")
EXIGENCES_AMAVIS = [
    ("P10.23-w : le constat — `GET /amavis[1]: Blocked INFECTED` au port de soumission, rien",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "aucun" and "GET /amavis[" in e["ligne"] and "Blocked INFECTED" in e["ligne"]),
    ("P10.23-w : la même commande à postscreen, un blocage postscreen et rien de plus",
     lambda e: e["famille"] == "postscreen" and e["verdict"] == "postscreen" and "amavis[" in e["ligne"]),
    ("P10.23-w : un verdict amavis dans le `helo` d'un rejet, un rejet",
     lambda e: e["famille"] == "smtpd" and e["verdict"] == "rejet" and "helo=<amavis[" in e["ligne"]),
    ("P10.23-w : un verdict amavis dans un message Dovecot, rien",
     lambda e: e["famille"] == "dovecot" and e["verdict"] == "aucun" and "amavis[" in e["ligne"]),
    ("P10.23-w : une panne d'antivirus écrite par le client (`WARN`), rien",
     lambda e: e["famille"] != "amavis" and e["verdict"] == "aucun" and "virus scanners failed" in e["ligne"]),
    ("P10.23-w : une panne d'antivirus écrite par le client (`av-scanner FAILED`), rien",
     lambda e: e["famille"] != "amavis" and e["verdict"] == "aucun" and "av-scanner FAILED" in e["ligne"]),
    ("P10.23-w : un verdict dans un nom de pièce jointe recopié par amavis (`p.path`), rien",
     lambda e: _amavis(e, "aucun", " p.path ", ") Blocked INFECTED (")),
    ("P10.23-w : une panne dans un nom de pièce jointe recopié par amavis (`p.path`), rien",
     lambda e: _amavis(e, "aucun", " p.path ", ") (!)WARN: all primary virus scanners failed", ") (!)ClamAV-clamd av-scanner FAILED: ")),
] + [
    (f"P10.23-w : la catégorie `{cat}` de l'entrée principale, lue", lambda e, cat=cat: e["verdict"] != "aucun" and _tete_amavis(e)[1] == cat)
    for cat in CATEGORIES_AMAVIS
] + [
    (f"P10.23-w : une entrée `{mot}`", lambda e, mot=mot: e["verdict"] != "aucun" and _tete_amavis(e)[0] == mot)
    for mot in ("Passed", "Blocked")
] + [
    ("P10.23-w : plusieurs virus dans une entrée", lambda e: e["verdict"] == "malware" and ", " in e["champs"].get("virus", "")),
    ("P10.23-w : plusieurs destinataires, le premier est le `user`",
     lambda e: e["famille"] == "amavis" and e["user"] and f"-> <{e['user']}>,<" in e["ligne"]),
    ("P10.23-w : un score par destinataire (`min..max`)", lambda e: ".." in e["champs"].get("score", "")),
    ("P10.23-w : `$log_verbose_templ` (`<proto>/<proto>`, `b:`), champs lus",
     lambda e: _amavis(e, "flux-passe", "ESMTP/ESMTP <", ", b: ") and e["champs"].get("size")),
    ("P10.23-w : une adresse relais IPv6", lambda e: e["famille"] == "amavis" and ":" in e["ip"]),
    ("P10.23-w : banque de politique et `LOCAL` avant l'adresse relais",
     lambda e: e["famille"] == "amavis" and e["ip"] and " LOCAL [" + e["ip"] + "]:" in e["ligne"]),
    ("P10.23-w : sans `[<a>]:<port>`, `[<e>]` (en-têtes `Received:`) n'est pas l'adresse source",
     lambda e: e["famille"] == "amavis" and e["verdict"] != "aucun" and not e["ip"] and e["champs"].get("size")
     and re.search(r"\}, \[[0-9.]+\] <", e["ligne"])),
    ("P10.23-w : un faux délimiteur dans le nom d'une pièce jointe bannie, aucune adresse",
     lambda e: _amavis(e, "banni", "FORGEDID") and not e["ip"] and e["ligne"].endswith(" ms")),
    ("P10.23-w : un crochet et une flèche dans le nom d'une pièce jointe bannie, champs d'amavis",
     lambda e: _amavis(e, "banni", ",[198.51.100.7] ") and e["ip"] and e["user"]),
    ("P10.23-w : un Message-ID qui recopie `mail_id:`, clé de repli (passage)",
     lambda e: _amavis(e, "flux-passe", "Message-ID: <x, mail_id: FORGED") and e["champs"].get("dedup") == REPLI_DE_DEDOUBLONNAGE),
    ("P10.23-w : le même Message-ID sur un malware, clé de repli (il n'est plus écarté)",
     lambda e: _amavis(e, "malware", "Message-ID: <y, mail_id: FORGED") and e["champs"].get("dedup") == REPLI_DE_DEDOUBLONNAGE),
    ("P10.23-w : un expéditeur qui recopie ` -> <…>,`, expéditeur et destinataire tus",
     lambda e: _amavis(e, "flux-passe", '<"a -> <') and e["champs"].get("rcpt") == "" and e["ip"]),
    ("P10.23-w, P10.24-i : une entrée coupée à 980 octets, verdict et relais seulement, et `truncated=1`",
     lambda e: _amavis(e, "flux-passe", "FORGED") and e["ligne"].endswith("...") and e["ip"] and not e["champs"].get("size")
     and e["champs"].get("truncated") == "1"),
    ("P10.23-w : la suite d'une entrée coupée, rien",
     lambda e: e["famille"] == "amavis" and e["verdict"] == "aucun" and re.match(r"\([^ ()]+\) \.\.\.", e["message"])),
    ("P10.23-w, P10.24-i : une entrée BANNED coupée (faux délimiteur dans le premier morceau), verdict seul, `truncated=1`",
     lambda e: _amavis(e, "banni", "FORGED") and e["ligne"].endswith("...") and not e["ip"]
     and e["champs"].get("truncated") == "1"),
    ("P10.24-i : une entrée BANNED coupée dont le délimiteur `) {…}, ` tombe ENTIER dans la suite, verdict seul, `truncated=1`",
     lambda e: _amavis(e, "banni") and e["champs"].get("truncated") == "1" and not e["ip"]
     and not re.search(r"[)] [{][A-Za-z,]*[}], ", e["message"])),
    ("P10.24-h : une entrée coupée retombe sur la clé de repli (empreinte)",
     lambda e: e["famille"] == "amavis" and e["champs"].get("truncated") == "1"
     and e["champs"].get("dedup") == REPLI_DE_DEDOUBLONNAGE),
    ("P10.23-w : l'entrée par destinataire (`$log_recip_templ`), rien",
     lambda e: e["famille"] == "amavis" and e["verdict"] == "aucun" and ", tag=" in e["ligne"]),
    ("P10.23-w : `av-scanner FAILED` avec l'adresse du démon clamd, panne sans adresse",
     lambda e: _amavis(e, "panne-av", " av-scanner FAILED: ", "[::1]:") and not e["ip"]),
    ("P10.23-w : `WARN: all primary virus scanners failed`, panne",
     lambda e: _amavis(e, "panne-av", "(!)WARN: all primary virus scanners failed")),
    ("P10.23-w : `(!!)AV: ALL VIRUS SCANNERS FAILED` (suit toujours le WARN), rien",
     lambda e: _amavis(e, "aucun", "(!!)AV: ALL VIRUS SCANNERS FAILED")),
]


def _mail_id_lu(e):
    """L'identifiant qu'une entrée amavis ATTEND dans sa clé (`mail-<id>-…`), ou None (clé de repli)."""
    d, verdict = e["champs"].get("dedup", ""), e["champs"].get("verdict", "")
    suffixe = "-" + verdict.replace(" ", "-", 1)
    return d[5:-len(suffixe)] if verdict and d.startswith("mail-") and d.endswith(suffixe) else None


def _meme_message_amavis(a, b):
    """P10.24-j — `Passed` et `Blocked` d'un même mail_id (les deux blocs de `$log_short_templ`)."""
    return (a["famille"] == b["famille"] == "amavis" and _tete_amavis(a)[0] == "Passed"
            and _tete_amavis(b)[0] == "Blocked" and _mail_id_lu(a) is not None and _mail_id_lu(a) == _mail_id_lu(b))


def _entree_complete(e):
    return re.search(r", \d+ ms$", e["ligne"]) is not None


def voisinage_des_entrees_coupees(entrees):
    """P10.24-i — `coupee` est une GLOBALE du programme awk : posé après un retour anticipé de `lire_amavis`
    (ou jamais remis à zéro), il garde la valeur de l'entrée PRÉCÉDENTE. Un témoin d'entrée coupée ne mord
    donc que si l'entrée lue juste avant lui (dans l'ordre du journal, celui du corpus) est COMPLÈTE et lue
    jusqu'au bout — adresse relais attendue, donc aucun retour anticipé — ; et une entrée complète doit
    suivre une entrée coupée. Les lignes lues par `lire_amavis` sont les entrées principales (verdict amavis
    hors panne) : une ligne `aucun` n'y passe jamais (le bras amavis émet toujours)."""
    lues = [e for e in entrees if e["famille"] == "amavis" and e["verdict"] in VERDICTS_AMAVIS and e["verdict"] != "panne-av"]
    manques = [f"P10.24-i : l'entrée coupée ligne {e['n']} ne suit pas une entrée complète lue jusqu'au bout (adresse "
               "relais attendue) — `coupee` est une globale awk, le témoin ne mordrait que par l'ordre du corpus"
               for avant, e in zip([None] + lues, lues)
               if not _entree_complete(e) and not (avant and _entree_complete(avant) and avant["ip"])]
    if not any(not _entree_complete(a) and _entree_complete(b) for a, b in zip(lues, lues[1:])):
        manques.append("P10.24-i : aucune entrée complète ne suit une entrée coupée — un `coupee` jamais remis à zéro resterait vert")
    return manques


def plancher_amavis(entrees):
    manques = [nom for nom, vrai in EXIGENCES_AMAVIS if not any(vrai(e) for e in entrees)]
    if not any(_meme_message_amavis(a, b) for a in entrees for b in entrees):
        manques.append("P10.24-j : `Passed` et `Blocked` d'un même mail_id, deux clés")
    return manques + voisinage_des_entrees_coupees(entrees)


def _rafale_sasl(a, b):
    """P10.24-h — deux échecs SASL de la même adresse, dans la même seconde, sur deux comptes."""
    return (a["famille"] == b["famille"] == "smtpd" and a["verdict"] == b["verdict"] == "echec"
            and a["epoch"] == b["epoch"] and a["ip"] == b["ip"] and a["user"] and b["user"] and a["user"] != b["user"])


def plancher_client(entrees):
    manques = [nom for nom, vrai in EXIGENCES_CLIENT if not any(vrai(e) for e in entrees)]
    if not any(_rafale_sasl(a, b) for a in entrees for b in entrees):
        manques.append("P10.24-h : deux échecs SASL de la même adresse dans la même seconde, sur deux comptes")
    return manques


def epreuve_de_la_validation():
    """La validation, éprouvée sur des lignes FABRIQUÉES : la conforme passe, chaque écart est refusé."""
    tete = "2026-09-23T19:00:00.000000+02:00 mailserver "
    conforme = ("rejet\t-\t2001:db8::7\tclient-postfix\t" + tete + "postfix/smtpd[1]: NOQUEUE: reject: RCPT from "
                "unknown[2001:db8::7]: 554 5.7.1 <b@example.test>: Relay access denied; from=<a@example.test> "
                "to=<b@example.test> proto=ESMTP helo=<auth failed>")
    # P10.23-i — une connexion Dovecot CLASSÉE sans `rip=` : comptée sans adresse, sous `auth`.
    dovecot_sans_rip = ("sans-adresse\tghost@example.test\t-\tfabriquee-dovecot-sans-rip\t" + tete + "dovecot: imap-login: "
                        "Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<ghost@example.test>, "
                        "method=PLAIN, session=<x>")
    for ligne in (conforme, dovecot_sans_rip):
        _, f = analyser_ligne(1, ligne, SPEC_CLIENT)
        if f:
            return f"une ligne CONFORME est refusée : {f}"
    ecarts = {
        "une adresse IPv6 hors de la plage de documentation": conforme.replace("helo=<auth failed>", "helo=<[2001:4860::8888]>"),
        "une adresse attendue sous la forme mappée": conforme.replace("\t2001:db8::7\t", "\t::ffff:192.0.2.7\t"),
        "un utilisateur attendu sur une ligne Postfix": conforme.replace("rejet\t-\t", "rejet\tb@example.test\t"),
        "un texte du client déclaré échec": conforme.replace("rejet\t", "echec\t", 1),
        "une adresse attendue absente des crochets": conforme.replace("\t2001:db8::7\t", "\t2001:db8::8\t"),
        "une provenance Dovecot sur une ligne Postfix": conforme.replace("\tclient-postfix\t", "\tsources-2.4.1\t"),
        "une ligne smtpd déclarée `postscreen`": conforme.replace("rejet\t", "postscreen\t", 1),
        "une ligne Dovecot déclarée `rejet`": ("rejet\t-\t192.0.2.105\tfabriquee-2.3\t" + tete + "dovecot: imap-login: ID sent: "
                                              "name=NOQUEUE: reject: user=<>, rip=192.0.2.105, lip=192.0.2.1"),
        # P10.23-i — le client est le PREMIER crochet ; une ligne sans adresse n'a pas de client lisible.
        "une adresse attendue qui n'est pas le premier crochet": conforme.replace("\t2001:db8::7\t", "\t198.51.100.9\t").replace(
            "helo=<auth failed>", "helo=<[198.51.100.9]>"),
        "une ligne `sans-adresse` dont le client est une adresse": conforme.replace("rejet\t-\t2001:db8::7\t", "sans-adresse\t-\t-\t"),
        "une ligne `sans-adresse` Dovecot que le capteur ne classe pas": (
            "sans-adresse\t-\t-\tfabriquee-2.3\t" + tete + "dovecot: imap-login: ID sent: name=x, user=<>, lip=192.0.2.1"),
        "une ligne `sans-adresse` Dovecot dont le `rip=` du serveur est une adresse": dovecot_sans_rip.replace(
            ", session=", ", rip=192.0.2.9, lip=192.0.2.1, session="),
        "une ligne `sans-adresse` du relais sortant (`smtp`)": (
            "sans-adresse\t-\t-\tsources-postfix\t" + tete + "postfix/smtp[2]: 4ABCDEF123: to=<c@example.net>, "
            "relay=none, delay=1, status=deferred (SASL authentication failed; server unknown[unknown] said: 535)"),
    }
    for nom, ligne in ecarts.items():
        if not analyser_ligne(1, ligne, SPEC_CLIENT)[1]:
            return f"la validation laisse passer « {nom} »"
    # P10.23-h — un échec SASL de smtpd conforme passe (son nom est lu), et chaque écart sur le nom est refusé.
    sasl = ("echec\tdave@example.test\t192.0.2.70\tsources-postfix\t" + tete + "postfix/submission/smtpd[2]: warning: "
            "unknown[192.0.2.70]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=dave@example.test")
    _, f = analyser_ligne(1, sasl, SPEC_CLIENT)
    if f:
        return f"un échec SASL CONFORME est refusé : {f}"
    ecarts_sasl = {
        "un nom attendu sur un échec SASL sans `, sasl_username=`": sasl.replace(", sasl_username=dave@example.test", ""),
        "un nom attendu quand `, sasl_username=` figure deux fois": sasl.replace(
            "(reason unavailable), sasl_username=dave", "x, sasl_username=eve@example.test, sasl_username=dave"),
        "un nom `(unavailable)` attendu": sasl.replace("dave@example.test", "(unavailable)"),
        "un nom attendu qui n'est pas celui de la ligne": sasl.replace("echec\tdave@example.test", "echec\teve@example.test"),
        "un nom attendu sur un rejet qui recopie `, sasl_username=`": conforme.replace("rejet\t-\t", "rejet\tceo@example.test\t").replace(
            "helo=<auth failed>", "helo=<x, sasl_username=ceo@example.test>"),
        "un nom SASL hors de `example.test`": sasl.replace("dave@example.test", "dave@example.org"),
    }
    for nom, ligne in ecarts_sasl.items():
        if not analyser_ligne(1, ligne, SPEC_CLIENT)[1]:
            return f"la validation laisse passer « {nom} »"
    # P10.23-w — une ligne amavis conforme passe, et chaque écart à la forme d'amavis est refusé.
    tete_am = "2026-09-24T11:02:01.123456+02:00 mailserver amavis[4101]: "
    entree_am = (tete_am + "(04101-01) Blocked INFECTED (Eicar-Signature) {DiscardedInbound}, [192.0.2.110]:40110 "
                 "[192.0.2.110] <a@example.net> -> <b@example.test>, Queue-ID: 4ABCDEF201, Message-ID: <x, mail_id: "
                 "FORGEDID9, Hits: -9, size: 1@example.net>, mail_id: AbCdEfGh0101, Hits: -, size: 2345, 45 ms")
    champs_am = ("verdict=Blocked INFECTED;virus=Eicar-Signature;sender=a@example.net;rcpt=b@example.test;score=;size=2345;"
                 "dedup=mail-AbCdEfGh0101-Blocked-INFECTED")
    conforme_am = "\t".join(("malware", "b@example.test", "192.0.2.110", "sources-amavis", champs_am, entree_am))
    _, f = analyser_ligne(1, conforme_am, SPEC_AMAVIS)
    if f:
        return f"une ligne amavis CONFORME est refusée : {f}"
    ecarts_am = {
        "une ligne smtpd déclarée `malware`": "\t".join((
            "malware", "-", "192.0.2.30", "client-postfix", "-", "2026-09-24T11:00:01.123456+02:00 mailserver "
            "postfix/submission/smtpd[3101]: warning: non-SMTP command from unknown[192.0.2.30]: GET /amavis[1]: "
            "Blocked INFECTED (Eicar-Signature) HTTP/1.1")),
        "une adresse attendue hors de la forme d'amavis (`[<e>]`)": conforme_am.replace("\t192.0.2.110\t", "\t192.0.2.111\t").replace(
            "[192.0.2.110] <a@", "[192.0.2.111] <a@"),
        "un `user` qui n'est pas le premier destinataire": conforme_am.replace("malware\tb@example.test", "malware\tc@example.test"),
        "un destinataire absent de ` -> <…>,`": conforme_am.replace("rcpt=b@example.test", "rcpt=c@example.test").replace(
            "malware\tb@example.test", "malware\tc@example.test"),
        "une valeur marquée `FORGED` attendue": conforme_am.replace("dedup=mail-AbCdEfGh0101-", "dedup=mail-FORGEDID9-"),
        "une clé qu'aucun `mail_id:` de la ligne ne porte": conforme_am.replace("dedup=mail-AbCdEfGh0101-", "dedup=mail-AbCdEfGh9999-"),
        # P10.24-j — la clé porte le verdict et la catégorie de l'entrée, et eux seuls.
        "la clé d'avant, `mail-<id>` sans verdict ni catégorie": conforme_am.replace("-Blocked-INFECTED", ""),
        "une clé au verdict d'une autre entrée": conforme_am.replace("-Blocked-INFECTED", "-Passed-INFECTED"),
        # P10.24-i — `truncated=1` sur une entrée coupée, et sur elle seule.
        "`truncated` attendu sur une entrée complète": conforme_am.replace("dedup=mail-", "truncated=1;dedup=mail-"),
        "une entrée coupée sans `truncated`": conforme_am.replace(", 45 ms", ", 4...").replace(
            "score=;size=2345", "score=;size=").replace("dedup=mail-AbCdEfGh0101-Blocked-INFECTED", f"dedup={REPLI_DE_DEDOUBLONNAGE}"),
        "un score et une taille lus ailleurs qu'en `, Hits: …, size: …`": conforme_am.replace("score=;size=2345", "score=;size=2346"),
        "un virus absent de `INFECTED (…) {`": conforme_am.replace("virus=Eicar-Signature", "virus=Autre"),
        "un champ `virus` sur une entrée qui n'est pas un malware": conforme_am.replace("malware\t", "banni\t", 1),
        "un verdict absent de la tête du message": conforme_am.replace("verdict=Blocked INFECTED", "verdict=Passed INFECTED"),
        "une panne d'antivirus avec une adresse": "\t".join((
            "panne-av", "-", "192.0.2.110", "sources-amavis", f"dedup={REPLI_DE_DEDOUBLONNAGE}",
            tete_am + "(04101-01) (!)WARN: all primary virus scanners failed, considering backups")),
        "des champs amavis attendus sur une ligne Postfix": "\t".join((
            "aucun", "-", "-", "client-postfix", f"dedup={REPLI_DE_DEDOUBLONNAGE}", "2026-09-24T11:00:01.123456+02:00 mailserver "
            "postfix/submission/smtpd[3101]: warning: non-SMTP command from unknown[192.0.2.30]: GET /x HTTP/1.1")),
    }
    for nom, ligne in ecarts_am.items():
        if not analyser_ligne(1, ligne, SPEC_AMAVIS)[1]:
            return f"la validation laisse passer « {nom} »"
    # P10.24-i — le voisinage des entrées coupées : un ordre conforme passe, chaque écart est refusé.
    def am(n, coupee, ip="192.0.2.1"):
        return dict(n=n, famille="amavis", verdict="flux-passe", ip=ip, ligne="x" + ("..." if coupee else ", 5 ms"))
    if voisinage_des_entrees_coupees([am(1, False), am(2, True), am(3, False)]):
        return "le voisinage des entrées coupées refuse un ordre CONFORME"
    ecarts_voisinage = {
        "une entrée coupée derrière une entrée coupée": [am(1, False), am(2, True), am(3, True), am(4, False)],
        "une entrée coupée derrière une entrée complète arrêtée avant l'adresse": [am(1, False, ip=""), am(2, True), am(3, False)],
        "une entrée coupée en tête": [am(1, True), am(2, False)],
        "aucune entrée complète après une entrée coupée": [am(1, False), am(2, True)],
    }
    for nom, lues in ecarts_voisinage.items():
        if not voisinage_des_entrees_coupees(lues):
            return f"le voisinage des entrées coupées laisse passer « {nom} »"
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
        if ev.get("severity") != SEVERITE_DU_VERDICT[e["verdict"]]:
            fautes.append(f"{quoi} : sévérité {ev.get('severity')} au lieu de {SEVERITE_DU_VERDICT[e['verdict']]}")
        # P10.23-w — chaque champ amavis attendu, et aucun autre ; la clé de dédoublonnage.
        attendus = e.get("champs") or {}
        for cle in CHAMPS_AMAVIS:
            if cle in attendus and champs.get(cle) != attendus[cle]:
                fautes.append(f"{quoi} : `{cle}` = `{champs.get(cle)}` au lieu de `{attendus[cle]}`")
            elif cle not in attendus and cle in champs:
                fautes.append(f"{quoi} : champ `{cle}` = `{champs.get(cle)}` émis, non attendu")
        # P10.24-h — la clé de TOUT événement : celle qu'attend le corpus amavis, sinon la clé de repli,
        # recalculée ici depuis la seule ligne (ce qui tient aussi l'absorption d'un rejeu : la clé ne
        # dépend ni de l'instant du passage, ni de son rang).
        cle = attendus.get("dedup", REPLI_DE_DEDOUBLONNAGE)
        if cle == REPLI_DE_DEDOUBLONNAGE:
            cle = cle_de_repli(e.get("epoch"), e["ip"], classe[1], e["ligne"])
        if ev.get("dedup") != cle:
            fautes.append(f"{quoi} : clé de dédoublonnage `{ev.get('dedup')}` au lieu de `{cle}`")
    for message, vus in par_message.items():
        fautes.append(f"{len(vus)} événement(s) pour un message absent des corpus : `{str(message)[:120]}`")
    # P10.24-h et P10.24-j — deux événements sous la même clé : l'ingestion (`INSERT OR IGNORE` sur
    # `event.dedup`, cloisonné par hôte) n'en garderait qu'un.
    par_cle = {}
    for ev in evenements:
        par_cle.setdefault(ev.get("dedup"), []).append(ev)
    for cle, vus in par_cle.items():
        if len(vus) > 1:
            fautes.append(f"{len(vus)} événements sous la même clé `{cle}` — l'ingestion n'en garderait qu'un "
                          f"(`{str(vus[1].get('message'))[:100]}` serait écarté)")
    return fautes


# P10.23-i — l'aveu des lignes classées sans adresse : sa forme, son canal, et son compte.
MOTIF_DU_COMPTE = re.compile(r"LIGNES CLASSÉES NON ÉMISES : (\d+) ligne\(s\)")


SEVERITE_DE_L_AVEU = 2   # des événements PERDUS : un trou de couverture (`plume_adresse_illisible`)
# Le passage d'épargne : `PLUME_MAIL_SKIP_IP` posé sur l'adresse de lignes classées du corpus.
ADRESSE_EPARGNEE = "192.0.2.70"


def _classee_hors_amavis(e):
    """Une ligne auth, postscreen ou rejet : celles que `PLUME_MAIL_SKIP_IP` écarte (amavis l'ignore)."""
    return e["verdict"] in ("succes", "echec", "rejet", "postscreen")


def categorie_sans_adresse(e):
    """La catégorie sous laquelle le capteur compte une ligne `sans-adresse` (ventilation de l'aveu)."""
    if e["famille"] == "dovecot" or (e["famille"] == "smtpd" and ECHEC_SASL_SMTPD.match(e["message"])):
        return "auth"
    if e["famille"] == "postscreen" and not e["message"].startswith("NOQUEUE: reject: "):
        return "postscreen"
    return "reject"


def juger_aveu(entrees, aveux):
    sans = [e for e in entrees if e["verdict"] == "sans-adresse"]
    partiels = [a for a in aveux if (a.get("fields") or {}).get("reason") == "unreadable-address"]
    if not sans:
        return [f"aveu `unreadable-address` émis alors qu'aucune ligne n'est sans adresse : {partiels[0].get('fields')}"] if partiels else []
    if len(partiels) != 1:
        return [f"{len(partiels)} aveu(x) `unreadable-address` au lieu d'un pour {len(sans)} ligne(s) `sans-adresse`"]
    champs, fautes = partiels[0].get("fields") or {}, []
    if partiels[0].get("severity") != SEVERITE_DE_L_AVEU:
        fautes.append(f"aveu des lignes sans adresse de sévérité {partiels[0].get('severity')} au lieu de {SEVERITE_DE_L_AVEU} "
                      "— ce sont des événements perdus")
    if partiels[0].get("source") != "mail" or champs.get("collector") != "mail":
        fautes.append(f"aveu des lignes sans adresse sous la source `{partiels[0].get('source')}`/`{champs.get('collector')}` "
                      "au lieu de `mail`")
    if champs.get("collect_status") != "partial" or champs.get("type") != "collector-availability":
        fautes.append(f"aveu des lignes sans adresse sous `{champs.get('type')}`/`{champs.get('collect_status')}` au lieu de "
                      "`collector-availability`/`partial` — `unavailable` ferait alerter la règle livrée sur une source saine")
    compte = MOTIF_DU_COMPTE.search(champs.get("detail", ""))
    if not compte or int(compte.group(1)) != len(sans):
        fautes.append(f"aveu des lignes sans adresse au compte `{compte.group(1) if compte else '?'}` au lieu de {len(sans)}")
    ventilation = {c: sum(1 for e in sans if categorie_sans_adresse(e) == c) for c in ("auth", "postscreen", "reject")}
    attendue = ",".join(f"{c}={n}" for c, n in ventilation.items())
    if f"Ventilation : {attendue}." not in champs.get("detail", ""):
        fautes.append(f"aveu des lignes sans adresse sans la ventilation `{attendue}` : `{champs.get('detail', '')[:200]}`")
    return fautes


def cle_d_aveu(aveux):
    """La clé de dédoublonnage de l'aveu `unreadable-address`, SANS son seau horaire (`-<ts/3600>`)."""
    for a in aveux or []:
        if (a.get("fields") or {}).get("reason") == "unreadable-address":
            return re.sub(r"-\d+$", "", str(a.get("dedup")))
    return None


def juger_cle_d_aveu(aveux_a, aveux_b):
    """Deux passages aux comptes DIFFÉRENTS rendent la même clé, au seau horaire près : elle porte la source,
    pas le nombre — sinon le dédoublonnage horaire ne joue plus et l'aveu bat à chaque passage (leçon de
    `plume_collecte_tronquee`). L'absence d'un aveu est jugée par `juger_aveu`."""
    a, b = cle_d_aveu(aveux_a), cle_d_aveu(aveux_b)
    if a is None or b is None or a == b:
        return []
    return [f"aveu des lignes sans adresse sous la clé `{a}` puis `{b}` pour deux comptes différents — la clé porte le "
            "nombre, le dédoublonnage horaire ne joue plus"]


def epreuve_du_juge():
    """Témoins sur des événements FABRIQUÉS : le juge doit se taire sur l'exact et accuser chaque écart."""
    def ev(ligne, cat, action, user, ip, service, sev, dedup=None, **amavis):
        return {"source": "mail", "category": cat, "severity": sev, "src_ip": ip, "message": ligne, "dedup": dedup,
                "fields": {"action": action, "user": user, "src_ip": ip, "service": service, **amavis}}
    def entree(n, verdict, user, ip, service, ligne, champs=None):
        return dict(n=n, corpus="x", verdict=verdict, user=user, ip=ip, provenance="x", service=service, ligne=ligne,
                    champs=champs or {}, epoch=1790240000)
    champs_l5 = dict(verdict="Blocked INFECTED", virus="V", sender="a@example.net", rcpt="b@example.test", score="",
                     size="1", dedup="mail-X-Blocked-INFECTED")
    champs_l6 = dict(verdict="Passed CLEAN", sender="", rcpt="", score="", size="", truncated="1", dedup=REPLI_DE_DEDOUBLONNAGE)
    corpus = [
        entree(1, "succes", "a@example.test", "192.0.2.1", "dovecot", "L1"),
        entree(2, "echec", "b@example.test", "192.0.2.2", "dovecot", "L2"),
        entree(3, "aucun", "", "", "postfix", "L3"),
        entree(4, "rejet", "", "2001:db8::4", "postfix", "L4"),
        entree(5, "malware", "b@example.test", "192.0.2.5", "amavis", "L5", champs_l5),
        entree(6, "flux-passe", "", "192.0.2.6", "amavis", "L6", champs_l6),
        entree(7, "echec", "c@example.test", "192.0.2.2", "postfix", "L7"),
    ]
    am5 = dict(verdict="Blocked INFECTED", virus="V", sender="a@example.net", rcpt="b@example.test", score="", size="1")
    am6 = dict(verdict="Passed CLEAN", sender="", rcpt="", score="", size="", truncated="1")
    def repli(ligne, ip, action):
        return cle_de_repli(1790240000, ip, action, ligne)
    exact = [ev("L1", "auth", "success", "a@example.test", "192.0.2.1", "dovecot", 1, repli("L1", "192.0.2.1", "success")),
             ev("L2", "auth", "failure", "b@example.test", "192.0.2.2", "dovecot", 2, repli("L2", "192.0.2.2", "failure")),
             ev("L4", "reject", "blocked", "", "2001:db8::4", "postfix", 2, repli("L4", "2001:db8::4", "blocked")),
             ev("L5", "malware", "infected", "b@example.test", "192.0.2.5", "amavis", 4, "mail-X-Blocked-INFECTED", **am5),
             ev("L6", "mailflow", "pass", "", "192.0.2.6", "amavis", 1, repli("L6", "192.0.2.6", "pass"), **am6),
             ev("L7", "auth", "failure", "c@example.test", "192.0.2.2", "postfix", 2, repli("L7", "192.0.2.2", "failure"))]
    if juger(corpus, exact):
        return f"le juge accuse le résultat EXACT : {juger(corpus, exact)}"
    def remplace(i, e):
        return exact[:i] + [e] + exact[i + 1:]
    r6 = repli("L6", "192.0.2.6", "pass")
    ecarts = {
        "succès manquant": exact[1:],
        "succès rendu en échec": remplace(0, ev("L1", "auth", "failure", "a@example.test", "192.0.2.1", "dovecot", 1, repli("L1", "192.0.2.1", "failure"))),
        "rejet rendu en échec": remplace(2, ev("L4", "auth", "failure", "", "2001:db8::4", "postfix", 2, repli("L4", "2001:db8::4", "failure"))),
        "événement pour une ligne `aucun`": exact + [ev("L3", "auth", "failure", "", "192.0.2.3", "postfix", 2, repli("L3", "192.0.2.3", "failure"))],
        "`user` faux": remplace(0, ev("L1", "auth", "success", "z@example.test", "192.0.2.1", "dovecot", 1, repli("L1", "192.0.2.1", "success"))),
        "`src_ip` faux": remplace(2, ev("L4", "reject", "blocked", "", "198.51.100.9", "postfix", 2, repli("L4", "198.51.100.9", "blocked"))),
        "`service` faux": remplace(2, ev("L4", "reject", "blocked", "", "2001:db8::4", "dovecot", 2, repli("L4", "2001:db8::4", "blocked"))),
        "sévérité fausse": remplace(3, ev("L5", "malware", "infected", "b@example.test", "192.0.2.5", "amavis", 3, "mail-X-Blocked-INFECTED", **am5)),
        "virus faux": remplace(3, ev("L5", "malware", "infected", "b@example.test", "192.0.2.5", "amavis", 4, "mail-X-Blocked-INFECTED", **dict(am5, virus="W"))),
        "score faux": remplace(4, ev("L6", "mailflow", "pass", "", "192.0.2.6", "amavis", 1, r6, **dict(am6, score="-99"))),
        "clé de dédoublonnage fausse": remplace(3, ev("L5", "malware", "infected", "b@example.test", "192.0.2.5", "amavis", 4, "mail-FORGED", **am5)),
        "clé amavis d'avant (`mail-<id>`)": remplace(3, ev("L5", "malware", "infected", "b@example.test", "192.0.2.5", "amavis", 4, "mail-X", **am5)),
        "clé de repli fausse": remplace(4, ev("L6", "mailflow", "pass", "", "192.0.2.6", "amavis", 1, "mail-FORGED", **am6)),
        "clé de repli d'avant (sans empreinte)": remplace(1, ev("L2", "auth", "failure", "b@example.test", "192.0.2.2", "dovecot", 2,
                                                              "mail-1790240000-192.0.2.2-failure")),
        "`truncated` absent d'une entrée coupée": remplace(4, ev("L6", "mailflow", "pass", "", "192.0.2.6", "amavis", 1, r6,
                                                               **{k: v for k, v in am6.items() if k != "truncated"})),
        "champ amavis non attendu": remplace(4, ev("L6", "mailflow", "pass", "", "192.0.2.6", "amavis", 1, r6, **dict(am6, virus="V"))),
        "événement inventé": exact + [ev("L9", "auth", "success", "a@example.test", "192.0.2.1", "dovecot", 1, "mail-L9")],
    }
    for nom, evenements in ecarts.items():
        if not juger(corpus, evenements):
            return f"le juge n'accuse pas « {nom} »"
    # Deux événements sous la même clé, CHACUN conforme à sa ligne (le corpus attend la même clé sur deux
    # entrées, comme `mail-<id>` sur `Passed` et `Blocked` d'un même message) : seule la vue d'ensemble accuse.
    l10 = entree(10, "malware", "b@example.test", "192.0.2.5", "amavis", "L10", champs_l5)
    if not juger(corpus + [l10], exact + [ev("L10", "malware", "infected", "b@example.test", "192.0.2.5", "amavis", 4,
                                              "mail-X-Blocked-INFECTED", **am5)]):
        return "le juge n'accuse pas « deux événements sous la même clé »"
    # P10.23-i — l'aveu, jugé à part : exact, puis chaque écart.
    sans = [dict(entree(8, "sans-adresse", "", "", "postfix", "L8"), famille="smtpd", message="NOQUEUE: reject: RCPT from unknown[unknown]: x"),
            dict(entree(9, "sans-adresse", "", "", "postfix", "L9"), famille="smtpd", message="NOQUEUE: reject: RCPT from unknown[unknown]: y")]
    def aveu(statut="partial", compte=2, ventilation="auth=0,postscreen=0,reject=2", sev=2, source="mail", dedup="avail-mail-7-490000"):
        return {"category": "config", "severity": sev, "source": source, "dedup": dedup,
                "fields": {"type": "collector-availability", "collector": source, "collect_status": statut,
                           "reason": "unreadable-address", "detail": f"LIGNES CLASSÉES NON ÉMISES : {compte} ligne(s) ce passage. Ventilation : {ventilation}. x"}}
    if juger_aveu(corpus + sans, [aveu()]) or juger_aveu(corpus, []):
        return f"le juge de l'aveu accuse le résultat EXACT : {juger_aveu(corpus + sans, [aveu()]) or juger_aveu(corpus, [])}"
    ecarts_aveu = {
        "aveu absent": (corpus + sans, []),
        "aveu au mauvais compte": (corpus + sans, [aveu(compte=1)]),
        "aveu à la mauvaise ventilation": (corpus + sans, [aveu(ventilation="auth=2,postscreen=0,reject=0")]),
        "aveu sous `unavailable`": (corpus + sans, [aveu(statut="unavailable")]),
        "aveu en double": (corpus + sans, [aveu(), aveu()]),
        "aveu sans ligne à avouer": (corpus, [aveu()]),
        "aveu de sévérité fausse": (corpus + sans, [aveu(sev=0)]),
        "aveu d'une autre source": (corpus + sans, [aveu(source="web")]),
    }
    for nom, (entrees, aveux) in ecarts_aveu.items():
        if not juger_aveu(entrees, aveux):
            return f"le juge de l'aveu n'accuse pas « {nom} »"
    # La clé : le seau horaire peut changer entre deux passages, le reste non.
    if juger_cle_d_aveu([aveu()], [aveu(compte=1, dedup="avail-mail-7-490001")]):
        return "le juge de la clé d'aveu accuse deux passages qui ne diffèrent que par le seau horaire"
    if not juger_cle_d_aveu([aveu()], [aveu(compte=1, dedup="avail-mail-8-490000")]):
        return "le juge de la clé d'aveu n'accuse pas « une clé qui porte le nombre »"
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


def lancer(chemin_awk, entrees, epargnee=None):
    with tempfile.TemporaryDirectory(prefix="garde-mail-dovecot-") as bac:
        rep = {d: os.path.join(bac, d) for d in ("bin", "spool", "state")}
        for d in rep.values():
            os.makedirs(d)
        os.symlink(chemin_awk, os.path.join(rep["bin"], "awk"))
        journal = os.path.join(bac, "mail.log")
        with open(journal, "w", encoding="utf-8") as fh:
            fh.write("".join(e["ligne"] + "\n" for e in entrees))
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PLUME_", "LC_", "LANG"))}
        # P10.24-h — une locale UTF-8 : celle où gawk lit des CARACTÈRES. Un capteur qui calculerait son
        # empreinte par caractère y rendrait une autre clé que celle calculée ici, octet par octet.
        env.update(
            PATH=rep["bin"] + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            PLUME_LIB=LIB, PLUME_SPOOL=rep["spool"], PLUME_STATE=rep["state"],
            PLUME_MAIL_SRC="file", PLUME_MAIL_LOG=journal, PLUME_MAIL_MAX=str(len(entrees) + 10),
            LC_ALL="C.UTF-8",
        )
        if epargnee:
            env["PLUME_MAIL_SKIP_IP"] = epargnee
        r = subprocess.run(["sh", CAPTEUR], env=env, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            refus(f"le capteur a échoué sous `{chemin_awk}` (rc={r.returncode}) : {r.stderr.strip()[:300]}")
        evenements, aveux, enveloppes = [], [], 0
        for nom in sorted(os.listdir(rep["spool"])):
            if nom.startswith(".") or not nom.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(rep["spool"], nom), encoding="utf-8"))
            except (OSError, ValueError) as e:
                # Pas un refus : c'est le capteur qui a écrit une enveloppe que le démon ne lira pas.
                return None, None, f"enveloppe `{nom}` illisible comme JSON ({e}) — tout le passage est perdu"
            if doc.get("kind") != "events":
                continue
            enveloppes += 1
            evenements += [ev for ev in doc.get("events") or [] if ev.get("category") != "config"]
            aveux += [ev for ev in doc.get("events") or [] if ev.get("category") == "config"
                      and (ev.get("fields") or {}).get("type") == "collector-availability"]
        if enveloppes == 0:
            refus(f"le capteur n'a déposé aucune enveloppe d'événements sous `{chemin_awk}`")
        return evenements, aveux, None


def passage_d_epargne(entrees):
    """`(journal, attendues)` : les lignes classées à l'adresse épargnée — attendues SANS événement et HORS de
    l'aveu (l'enveloppe `collection-reducing` les déclare) — et une ligne classée d'une autre adresse, émise."""
    epargnees = [e for e in entrees if e["ip"] == ADRESSE_EPARGNEE and _classee_hors_amavis(e)]
    autre = [e for e in entrees if e["ip"] and e["ip"] != ADRESSE_EPARGNEE and _classee_hors_amavis(e)][:1]
    return epargnees + autre, [dict(e, verdict="aucun") for e in epargnees] + autre


def jouer(chemin_awk, entrees):
    """Les trois passages du capteur sous un awk, et leurs fautes. (1) Le corpus entier. (2) UNE seule ligne
    sans adresse : l'aveu part dès une ligne, et sous la même clé qu'au passage (1). (3) L'adresse épargnée
    (`PLUME_MAIL_SKIP_IP`) : ses lignes ne sont ni émises ni avouées, une autre adresse l'est."""
    evenements, aveux, illisible = lancer(chemin_awk, entrees)
    if illisible:
        return [illisible]
    fautes = juger(entrees, evenements) + juger_aveu(entrees, aveux)
    une = [e for e in entrees if e["verdict"] == "sans-adresse"][:1]
    ev1, av1, ill1 = lancer(chemin_awk, une)
    fautes += [f"(passage à une seule ligne sans adresse) {f}"
               for f in ([ill1] if ill1 else juger(une, ev1) + juger_aveu(une, av1) + juger_cle_d_aveu(aveux, av1))]
    journal, attendues = passage_d_epargne(entrees)
    ev2, av2, ill2 = lancer(chemin_awk, journal, epargnee=ADRESSE_EPARGNEE)
    fautes += [f"(passage PLUME_MAIL_SKIP_IP={ADRESSE_EPARGNEE}) {f}"
               for f in ([ill2] if ill2 else juger(attendues, ev2) + juger_aveu(journal, av2))]
    return fautes


def main():
    for f in (CAPTEUR, LIB, CORPUS_DOVECOT, CORPUS_CLIENT, CORPUS_AMAVIS):
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
    amavis = lire_corpus(CORPUS_AMAVIS, SPEC_AMAVIS, vues)
    manques = [f"{SPEC_DOVECOT['nom']} : {m}" for m in plancher_dovecot(dovecot)] + \
              [f"{SPEC_CLIENT['nom']} : {m}" for m in plancher_client(client)] + \
              [f"{SPEC_AMAVIS['nom']} : {m}" for m in plancher_amavis(amavis)]
    if manques:
        refus("corpus sous son plancher : " + " ; ".join(manques))
    entrees = dovecot + client + amavis
    awks = implementations_awk()
    if not awks:
        refus(f"aucune implémentation d'awk parmi {AWK_EXERCES}")
    # Des fonctions d'adresse introuvables empêchent CETTE épreuve, pas le jugement du corpus : un défaut
    # de classification mesuré l'emporte (1) ; sans défaut, leur absence fait refuser (2).
    fonctions, introuvables = fonctions_d_adresse_livrees()
    total = 0
    for nom, chemin in awks:
        fautes = [] if introuvables else epreuve_des_adresses(chemin, fonctions)
        fautes += jouer(chemin, entrees)
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
          f"({par_version['2.4']} en 2.4, {par_version['2.3']} en 2.3), les {len(client)} lignes d'adresses et de "
          f"texte du client ({len(EXIGENCES_CLIENT)} exigences de plancher) et les {len(amavis)} lignes amavis "
          f"({len(EXIGENCES_AMAVIS)} exigences) comme attendu — succès lus à l'en-tête Dovecot, blocages postscreen, "
          f"rejets et verdicts amavis lus sous leur étiquette et en tête du message, champs amavis lus dans leur "
          f"forme ou tus, nom SASL de smtpd lu à sa place ou tu, « Login aborted » et texte du client jamais verdict, "
          f"adresse entière (IPv6, mappée rendue en IPv4) au premier crochet, "
          f"{sum(1 for e in entrees if e['verdict'] == 'sans-adresse')} ligne(s) sans adresse comptées et avouées (aveu "
          f"dès une ligne, clé sans le nombre, adresse épargnée {ADRESSE_EPARGNEE} ni émise ni avouée), "
          f"clés recalculées et deux à deux distinctes, {len(TABLE_DES_ADRESSES)} valeurs d'adresse jugées, rien d'inventé. "
          f"Awk exercés : {exerces}" + (f" ; NON EXERCÉS (absents) : {absents}." if absents else "."))
    sys.exit(0)


if __name__ == "__main__":
    main()
