#!/usr/bin/env python3
"""Le capteur mail lit les verdicts d'authentification de l'EXPÉDITEUR, le courrier SORTANT, la file,
l'envoi authentifié réussi et le journal de ClamAV — garde de CI (`P10.32-f`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Constaté sur un journal docker-mailserver réel : `collectors/mail.sh` ne lisait que dovecot, smtpd,
postscreen et amavis. Il n'émettait RIEN pour opendkim, opendmarc, policyd-spf, `postfix/smtp`
(sortant), `postfix/qmgr` (file), l'envoi SMTP authentifié RÉUSSI (`client=…, sasl_method=…`), ni pour
le journal propre de clamd et de freshclam. Aucun échec DKIM/DMARC/SPF n'y était caché ce jour-là : le
défaut est une SURFACE NON OBSERVÉE — une usurpation, un compte volé qui envoie, une base antivirale
périmée y seraient invisibles.

CE QUE LA GARDE FAIT
--------------------
Elle lit SEPT corpus (`collectors/mail-opendkim.corpus`, `mail-opendmarc.corpus`,
`mail-policyd-spf.corpus`, `mail-sortant-postfix-smtp.corpus`, `mail-file-qmgr.corpus`,
`mail-soumission-authentifiee.corpus`, `mail-clamd.corpus`, `mail-freshclam.corpus` — huit fichiers, le
journal ClamAV ayant deux démons), les VALIDE (colonnes, vocabulaire, catégorie et sévérité accordées à
une table écrite ICI une seconde fois, étiquette de la ligne, domaines et adresses de documentation,
plancher d'exigences nommées), puis exécute le capteur TEL QU'IL EST LIVRÉ, en mode fichier, sous
chaque awk présent parmi `gawk` et `mawk`, et juge chaque ligne : exactement un événement, ou aucun ;
catégorie, action, sévérité, horodatage, `src_ip`, champs (égalité stricte du sac), clé de repli
recalculée depuis la seule ligne ; message égal à la ligne — ou, pour le sortant, à la ligne dont
chaque partie locale d'adresse est masquée (recalculé ici, et aucune partie locale ne doit subsister) ;
rien d'inventé.

Puis, toujours sur le capteur livré :
  * le FILIGRANE de ClamAV (heure murale sans décalage, une seconde partagée par plusieurs lignes) :
    trois passages sur un journal qui grandit ne rejouent aucune ligne et n'en sautent aucune ;
  * le DÉCALAGE : celui de mail.log par défaut, `PLUME_MAIL_CLAMAV_UTC_OFFSET` quand il est posé ;
  * les TROIS MODES : en `file`, le chemin par défaut est `/var/log/clamav/…` ; en `docker` et `k3s`,
    `/var/log/mail/…`, lus par `docker exec` / `kubectl exec` (simulés, la commande lancée DANS le
    conteneur est celle du capteur) ; un chemin par défaut absent est dit `absent` dans l'enveloppe de
    config, SANS aveu ; un chemin POSÉ absent est AVOUÉ ; une variable posée vide coupe la lecture.

CODES : 0 tout est tenu ; 1 un défaut mesuré ; 2 la garde refuse de conclure (instrument invalide,
corpus hors forme, aucun awk) — rien n'a été mesuré.

CE QU'ELLE NE TIENT PAS, DIT
----------------------------
Les formes `enonce`, `gabarit` et `fabriquee` ne sont pas relevées dans un journal réel : la garde tient
la lecture de CES formes, pas leur existence. Elle ne tient ni le retour à l'heure d'hiver (une heure
murale rejouée), ni une fenêtre `tail` qui couperait les lignes de la seconde du filigrane. Les autres
familles du capteur sont tenues par `check_mail_sensor_classifies_dovecot_logins_of_both_versions.py`.
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
ETIQUETTE = "P10.32-f"
AWK_EXERCES = ("gawk", "mawk")

# corpus -> (flux, étiquettes admises pour une ligne classée)
CORPUS = {
    "mail-opendkim.corpus": ("mail", ("opendkim",)),
    "mail-opendmarc.corpus": ("mail", ("opendmarc",)),
    "mail-policyd-spf.corpus": ("mail", ("policyd-spf",)),
    "mail-sortant-postfix-smtp.corpus": ("mail", ("smtp",)),
    "mail-file-qmgr.corpus": ("mail", ("qmgr",)),
    "mail-soumission-authentifiee.corpus": ("mail", ("smtpd",)),
    "mail-clamd.corpus": ("clamd", ("clamd",)),
    "mail-freshclam.corpus": ("freshclam", ("freshclam",)),
}
# (service, action) -> (catégorie, sévérité) : la table écrite une SECONDE fois, ici.
CLASSES = {
    ("opendkim", "pass"): ("mail", 1), ("opendkim", "signed"): ("mail", 1), ("opendkim", "none"): ("mail", 1),
    ("opendkim", "fail"): ("mail", 3), ("opendkim", "error"): ("mail", 2),
    ("opendmarc", "pass"): ("mail", 1), ("opendmarc", "bestguesspass"): ("mail", 1), ("opendmarc", "none"): ("mail", 1),
    ("opendmarc", "fail"): ("mail", 3), ("opendmarc", "temperror"): ("mail", 2), ("opendmarc", "permerror"): ("mail", 2),
    ("policyd-spf", "pass"): ("mail", 1), ("policyd-spf", "none"): ("mail", 1), ("policyd-spf", "neutral"): ("mail", 1),
    ("policyd-spf", "softfail"): ("mail", 2), ("policyd-spf", "fail"): ("mail", 3),
    ("policyd-spf", "temperror"): ("mail", 2), ("policyd-spf", "permerror"): ("mail", 2),
    ("smtp", "sent"): ("mail", 1), ("smtp", "deferred"): ("mail", 2), ("smtp", "bounced"): ("mail", 3),
    ("smtp", "ambiguous"): ("mail", 2),
    ("qmgr", "queued"): ("mail", 1), ("qmgr", "expired"): ("mail", 2),
    ("postfix", "success"): ("auth", 1),
    ("clamd", "infected"): ("malware", 4), ("clamd", "error"): ("av_error", 3),
    ("clamd", "selfcheck_failed"): ("av_error", 3), ("clamd", "reload_failed"): ("av_error", 3),
    ("clamd", "scan_error"): ("av_error", 3), ("clamd", "reloaded"): ("update", 1),
    ("clamd", "database_stale"): ("update", 3),
    ("freshclam", "outdated"): ("update", 2), ("freshclam", "update_failed"): ("update", 3),
    ("freshclam", "updated"): ("update", 1), ("freshclam", "database_stale"): ("update", 3),
}
PROVENANCES = ("mesuree-dms", "enonce", "gabarit", "fabriquee")
BASE_DE_L_EMPREINTE, MODULE_DE_L_EMPREINTE = 257, 2147483629
PLAGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                            "127.0.0.0/8", "2001:db8::/32", "::1/128")]
DOMAINE_DE_DOC = re.compile(r"^([a-z0-9-]+\.)*(example(\.(org|net|com))?|test)$")
HORODATAGE_MAIL = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?([+-]\d\d:\d\d) \S+ (\S+?)(?:\[\d+\])?: ")
HORODATAGE_CLAMAV = re.compile(r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                               r"([ 0-3]\d) (\d\d):(\d\d):(\d\d) (\d{4}) -> ")
MOIS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
QUADRUPLET = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{1,4}:){1,7}:?(?:[0-9A-Fa-f]{1,4})?)(?![0-9A-Za-z:])")
AROBASE = re.compile(r"@\[?([A-Za-z0-9.-]+)")
PARTIE_LOCALE_RESTANTE = re.compile(r"[^\s<>(),;:\"@\[*]@")

# Les exigences de plancher : chacune est une ligne qu'un capteur qui ne lit pas la famille, ou qui la
# lit mal, classerait faux.
def _ex(corpus, verdict, test=lambda e: True):
    return lambda e: e["corpus"] == corpus and e["verdict"] == verdict and test(e)
EXIGENCES = [
    ("opendkim : une signature fausse", _ex("mail-opendkim.corpus", "mail/fail")),
    ("opendkim : une vérification réussie", _ex("mail-opendkim.corpus", "mail/pass")),
    ("opendkim : l'absence de signature", _ex("mail-opendkim.corpus", "mail/none")),
    ("opendkim : une clé introuvable, son domaine lu", _ex("mail-opendkim.corpus", "mail/error", lambda e: e["champs"].get("domain"))),
    ("opendkim : `not internal` et `not authenticated` ne sont rien",
     lambda e: e["corpus"] == "mail-opendkim.corpus" and e["verdict"] == "aucun" and e["ligne"].endswith(": not authenticated")),
    ("opendkim : un verdict écrit par un client sous une autre étiquette n'est rien",
     lambda e: e["corpus"] == "mail-opendkim.corpus" and e["verdict"] == "aucun" and e["etiquette"] != "opendkim"),
    ("opendmarc : un `fail`", _ex("mail-opendmarc.corpus", "mail/fail")),
    ("opendmarc : un `pass` relevé", _ex("mail-opendmarc.corpus", "mail/pass", lambda e: e["provenance"] == "mesuree-dms")),
    ("opendmarc : un résultat suivi d'un texte n'est rien",
     lambda e: e["corpus"] == "mail-opendmarc.corpus" and e["verdict"] == "aucun" and e["etiquette"] == "opendmarc"),
    ("policyd-spf : un `Fail` à son adresse cliente", _ex("mail-policyd-spf.corpus", "mail/fail", lambda e: e["champs"].get("src_ip"))),
    ("policyd-spf : un `Softfail`", _ex("mail-policyd-spf.corpus", "mail/softfail")),
    ("policyd-spf : une adresse IPv6", _ex("mail-policyd-spf.corpus", "mail/temperror", lambda e: ":" in e["champs"].get("src_ip", ""))),
    ("policyd-spf : `envelope-from=` recopié par le HELO, domaine TU",
     _ex("mail-policyd-spf.corpus", "mail/fail", lambda e: e["ligne"].count("; envelope-from=") > 1 and not e["champs"].get("domain"))),
    ("policyd-spf : `client-ip=` recopié par le HELO, adresse TUE",
     _ex("mail-policyd-spf.corpus", "mail/fail", lambda e: e["ligne"].count("client-ip=") > 1 and not e["champs"].get("src_ip"))),
    ("sortant : un envoi réussi", _ex("mail-sortant-postfix-smtp.corpus", "mail/sent")),
    ("sortant : un rebond", _ex("mail-sortant-postfix-smtp.corpus", "mail/bounced")),
    ("sortant : un report sans relais (`relay=none`)", _ex("mail-sortant-postfix-smtp.corpus", "mail/deferred", lambda e: e["champs"].get("relay") == "none")),
    ("sortant (P10.22-v) : l'échec SASL de notre relais, différé et jamais un échec d'authentification",
     _ex("mail-sortant-postfix-smtp.corpus", "mail/deferred", lambda e: "SASL authentication failed" in e["ligne"] and not e["champs"].get("src_ip"))),
    ("sortant : une partie locale entre guillemets, masquée", _ex("mail-sortant-postfix-smtp.corpus", "mail/sent", lambda e: 'to=<"' in e["ligne"])),
    ("sortant : la suite recopiée par le destinataire, statut tu", _ex("mail-sortant-postfix-smtp.corpus", "mail/ambiguous", lambda e: 'to=<"x, relay=' in e["ligne"])),
    ("sortant : la suite recopiée par le serveur distant, statut tu", _ex("mail-sortant-postfix-smtp.corpus", "mail/ambiguous", lambda e: "said: 550 x, relay=" in e["ligne"])),
    ("sortant : `postfix/smtp-amavis/smtp` relevé, saut interne", lambda e: e["corpus"] == "mail-sortant-postfix-smtp.corpus" and e["verdict"] == "aucun" and e["etiquette"] == "postfix/smtp-amavis/smtp" and e["provenance"] == "mesuree-dms"),
    ("sortant : `postfix/smtp-amavis/smtp` vers un relais EXTERNE, rien (l'étiquette, pas le relais)",
     lambda e: e["corpus"] == "mail-sortant-postfix-smtp.corpus" and e["verdict"] == "aucun" and e["etiquette"] == "postfix/smtp-amavis/smtp" and "127.0.0.1" not in e["ligne"]),
    ("sortant : `postfix/lmtp`, saut interne", lambda e: e["corpus"] == "mail-sortant-postfix-smtp.corpus" and e["verdict"] == "aucun" and e["etiquette"] == "postfix/lmtp"),
    ("sortant : `postfix/smtp` vers la boucle locale, rien (le relais, pas l'étiquette)",
     lambda e: e["corpus"] == "mail-sortant-postfix-smtp.corpus" and e["verdict"] == "aucun" and e["etiquette"] == "smtp" and "relay=127." in e["ligne"]),
    ("file : une entrée en file relevée", _ex("mail-file-qmgr.corpus", "mail/queued", lambda e: e["provenance"] == "mesuree-dms")),
    ("file : une expiration", _ex("mail-file-qmgr.corpus", "mail/expired")),
    ("file : un expéditeur qui recopie la suite, lu en entier", _ex("mail-file-qmgr.corpus", "mail/queued", lambda e: "queue active)\"@" in e["ligne"])),
    ("envoi authentifié : IPv4", _ex("mail-soumission-authentifiee.corpus", "auth/success", lambda e: "." in e["champs"].get("src_ip", ""))),
    ("envoi authentifié : IPv6", _ex("mail-soumission-authentifiee.corpus", "auth/success", lambda e: ":" in e["champs"].get("src_ip", ""))),
    ("envoi authentifié : `sasl_sender=` après le nom, hors du nom", _ex("mail-soumission-authentifiee.corpus", "auth/success", lambda e: ", sasl_sender=" in e["ligne"])),
    ("envoi authentifié : un texte du client qui l'imite, rien",
     lambda e: e["corpus"] == "mail-soumission-authentifiee.corpus" and e["verdict"] == "aucun" and "sasl_method=" in e["ligne"]),
    ("clamd : un virus trouvé", _ex("mail-clamd.corpus", "malware/infected")),
    ("clamd : un auto-contrôle en échec", _ex("mail-clamd.corpus", "av_error/selfcheck_failed")),
    ("clamd : un rechargement raté", _ex("mail-clamd.corpus", "av_error/reload_failed")),
    ("clamd : un rechargement réussi relevé", _ex("mail-clamd.corpus", "update/reloaded", lambda e: e["provenance"] == "mesuree-dms")),
    ("clamd : un jour du mois sous dix, complété par une espace", lambda e: e["flux"] == "clamd" and e["verdict"] != "aucun" and re.match(r"^\S+ \S+  \d ", e["ligne"])),
    ("clamd : une ligne sans horodatage n'est rien", lambda e: e["flux"] == "clamd" and e["verdict"] == "aucun" and not HORODATAGE_CLAMAV.match(e["ligne"])),
    ("freshclam : une installation périmée relevée", _ex("mail-freshclam.corpus", "update/outdated", lambda e: e["provenance"] == "mesuree-dms")),
    ("freshclam : une mise à jour en échec", _ex("mail-freshclam.corpus", "update/update_failed")),
    ("freshclam : une base trop vieille", _ex("mail-freshclam.corpus", "update/database_stale")),
]


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — la garde REFUSE DE CONCLURE, rien n'a été mesuré.")
    sys.exit(2)


def empreinte(ligne):
    """L'empreinte que le capteur calcule (`empreinte` de `collectors/mail.sh`), écrite ICI une seconde fois."""
    h = 0
    for octet in ligne.encode("utf-8"):
        h = (h * BASE_DE_L_EMPREINTE + octet) % MODULE_DE_L_EMPREINTE
    return h


def masquer(ligne):
    """Le masquage du sortant (`masquer_adresses`), écrit ICI une seconde fois."""
    ligne = re.sub(r'"[^"]*"@', "*@", ligne)
    return re.sub(r'[^ <>(),;:"@\[]+@', "*@", ligne)


def decalage_en_secondes(d):
    signe = -1 if d[0] == "-" else 1
    return signe * (int(d[1:3]) * 3600 + int(d[4:6]) * 60)


def epoch_mail(ligne):
    m = HORODATAGE_MAIL.match(ligne)
    return int(datetime.datetime.fromisoformat(m.group(1) + m.group(2)).timestamp()) if m else None


def mur_clamav(ligne):
    m = HORODATAGE_CLAMAV.match(ligne)
    if not m:
        return None
    mois, jour, hh, mm, ss, an = m.groups()
    return int(datetime.datetime(int(an), MOIS[mois], int(jour), int(hh), int(mm), int(ss),
                                 tzinfo=datetime.timezone.utc).timestamp())


def etiquette_de(ligne, flux):
    if flux != "mail":
        return flux
    m = HORODATAGE_MAIL.match(ligne)
    if not m:
        return None
    e = m.group(3)
    if re.fullmatch(r"postfix(/[\w.-]+)*/smtpd", e):
        return "smtpd"
    if e == "postfix/smtp":
        return "smtp"
    if re.fullmatch(r"postfix(/[\w.-]+)*/qmgr", e):
        return "qmgr"
    return e


def lire_champs(texte):
    if texte == "-":
        return {}, []
    champs, fautes = {}, []
    for morceau in texte.split(";"):
        cle, egal, valeur = morceau.partition("=")
        if not egal or not re.fullmatch(r"[a-z_]+", cle):
            fautes.append(f"champ `{morceau}` illisible")
        elif cle in champs:
            fautes.append(f"champ `{cle}` en double")
        else:
            champs[cle] = valeur
    return champs, fautes


def adresses_de(ligne):
    vues = []
    for q in QUADRUPLET.findall(ligne):
        try:
            vues.append(ipaddress.ip_address(q))
        except ValueError:
            pass
    for s in IPV6.findall(ligne):
        if s.count(":") >= 2:
            try:
                vues.append(ipaddress.ip_address(s))
            except ValueError:
                pass
    return vues


def analyser(nom, n, texte, flux, etiquettes, vues):
    fautes = []
    col = texte.split("\t")
    if len(col) != 5:
        return None, [f"{nom} ligne {n} : {len(col)} colonnes au lieu de 5"]
    verdict, sev, texte_champs, provenance, ligne = col
    if ligne in vues:
        fautes.append(f"{nom} ligne {n} : ligne en double (deux événements sous la même clé)")
    vues.add(ligne)
    champs, f = lire_champs(texte_champs)
    fautes += [f"{nom} ligne {n} : {x}" for x in f]
    if provenance not in PROVENANCES:
        fautes.append(f"{nom} ligne {n} : provenance `{provenance}` hors vocabulaire {list(PROVENANCES)}")
    etiquette = etiquette_de(ligne, flux)
    if verdict == "aucun":
        if sev != "-" or champs:
            fautes.append(f"{nom} ligne {n} : une ligne `aucun` attend une sévérité `-` et aucun champ")
    else:
        cat, _, action = verdict.partition("/")
        service = champs.get("service")
        classe = CLASSES.get((service, action))
        if classe is None:
            fautes.append(f"{nom} ligne {n} : `{service}`/`{action}` hors de la table des classes")
        elif classe != (cat, int(sev) if sev.isdigit() else None):
            fautes.append(f"{nom} ligne {n} : `{verdict}` sévérité {sev} au lieu de `{classe[0]}/{action}` sévérité {classe[1]}")
        if etiquette not in etiquettes:
            fautes.append(f"{nom} ligne {n} : une ligne `{etiquette}` déclarée `{verdict}` — seule {etiquettes} classe ici")
        if flux == "mail" and epoch_mail(ligne) is None:
            fautes.append(f"{nom} ligne {n} : pas d'horodatage ISO avec décalage")
        if flux != "mail" and mur_clamav(ligne) is None:
            fautes.append(f"{nom} ligne {n} : pas d'horodatage ClamAV")
    for a in adresses_de(ligne) + [ipaddress.ip_address(v) for k, v in champs.items() if k == "src_ip" and v]:
        a = a.ipv4_mapped or a if a.version == 6 else a
        if not any(a in p for p in PLAGES):
            fautes.append(f"{nom} ligne {n} : adresse `{a}` hors des plages de documentation")
    for d in AROBASE.findall(ligne) + [v for k, v in champs.items() if k in ("domain", "rcpt_domain") and v]:
        if not QUADRUPLET.fullmatch(d) and not DOMAINE_DE_DOC.match(d.lower()):
            fautes.append(f"{nom} ligne {n} : domaine `{d}` hors des domaines de documentation")
    return dict(corpus=nom, n=n, flux=flux, verdict=verdict, sev=sev, champs=champs, provenance=provenance,
                ligne=ligne, etiquette=etiquette), fautes


def lire_corpus():
    entrees, fautes, vues = [], [], set()
    for nom, (flux, etiquettes) in CORPUS.items():
        chemin = os.path.join(RACINE, "collectors", nom)
        if not os.path.exists(chemin):
            refus(f"`collectors/{nom}` introuvable")
        for n, texte in enumerate(open(chemin, encoding="utf-8").read().split("\n"), 1):
            if not texte or texte.startswith("#"):
                continue
            e, f = analyser(nom, n, texte, flux, etiquettes, vues)
            fautes += f
            if e:
                entrees.append(e)
    return entrees, fautes


# --- LE JUGE --------------------------------------------------------------------------------------
def attendu(e, decalage):
    """L'événement attendu pour une entrée classée (sans le message pour le sortant : voir `juger`)."""
    cat, _, action = e["verdict"].partition("/")
    champs = dict(e["champs"])
    champs.setdefault("user", "")
    champs.setdefault("src_ip", "")
    champs["action"] = action
    ts = epoch_mail(e["ligne"]) if e["flux"] == "mail" else mur_clamav(e["ligne"]) - decalage
    message = masquer(e["ligne"]) if champs.get("service") == "smtp" else e["ligne"]
    return dict(category=cat, severity=int(e["sev"]), ts=ts, src_ip=champs["src_ip"], fields=champs,
                message=message, dedup=f"mail-{ts}-{champs['src_ip']}-{action}-{empreinte(e['ligne'])}")


def juger(entrees, evenements, decalage):
    fautes = []
    par_message = {}
    for ev in evenements:
        par_message.setdefault(ev.get("message"), []).append(ev)
    for e in entrees:
        quoi = f"{e['corpus']} ligne {e['n']} ({e['provenance']}, attendu `{e['verdict']}`)"
        if e["verdict"] == "aucun":
            vus = par_message.pop(e["ligne"], []) + par_message.pop(masquer(e["ligne"]), [])
            if vus:
                fautes.append(f"{quoi} : {len(vus)} événement(s) émis, `{vus[0].get('category')}`/{vus[0].get('fields', {}).get('action')}`")
            continue
        a = attendu(e, decalage)
        vus = par_message.pop(a["message"], [])
        if len(vus) != 1:
            fautes.append(f"{quoi} : {len(vus)} événement(s) au lieu d'un" + (" — ligne non classée" if not vus else ""))
            continue
        ev = vus[0]
        for cle in ("category", "severity", "ts", "src_ip", "dedup"):
            if ev.get(cle) != a[cle]:
                fautes.append(f"{quoi} : `{cle}` = `{ev.get(cle)}` au lieu de `{a[cle]}`")
        if (ev.get("fields") or {}) != a["fields"]:
            fautes.append(f"{quoi} : champs {json.dumps(ev.get('fields'), ensure_ascii=False)} au lieu de "
                          f"{json.dumps(a['fields'], ensure_ascii=False)}")
        if a["fields"].get("service") == "smtp" and PARTIE_LOCALE_RESTANTE.search(ev.get("message", "")):
            fautes.append(f"{quoi} : une partie locale d'adresse subsiste dans le message émis")
    for message, vus in par_message.items():
        fautes.append(f"{len(vus)} événement(s) pour un message absent des corpus : `{str(message)[:120]}`")
    return fautes


def epreuve_du_juge():
    """Le juge rougit sur des événements faux, et pas sur les bons — sinon la garde refuse de conclure."""
    ligne = "2026-10-14T03:00:01.100000+02:00 mx1 postfix/smtp[1]: 1A: to=<a@example.org>, relay=none, delay=1, delays=1/1/1/1, dsn=4.4.1, status=deferred (x)"
    e = dict(corpus="épreuve", n=1, flux="mail", verdict="mail/deferred", sev="2", provenance="fabriquee", ligne=ligne,
             champs={"service": "smtp", "rcpt_domain": "example.org", "relay": "none", "dsn": "4.4.1"})
    bon = dict(attendu(e, 0))
    bon["fields"] = dict(bon["fields"])
    if juger([e], [bon], 0):
        return "le juge accuse un événement juste"
    variantes = {
        "sévérité": dict(bon, severity=1), "catégorie": dict(bon, category="auth"),
        "clé": dict(bon, dedup="x"), "champ en trop": dict(bon, fields=dict(bon["fields"], rcpt="a@example.org")),
        "message non masqué": dict(bon, message=ligne), "horodatage": dict(bon, ts=bon["ts"] + 1),
    }
    for quoi, ev in variantes.items():
        if not juger([e], [ev], 0):
            return f"le juge ne voit pas un événement faux ({quoi})"
    if not juger([e], [], 0) or not juger([], [bon], 0):
        return "le juge ne voit pas un événement manquant, ou inventé"
    if masquer('to=<"a b"@example.org> <c.d@example.org>') != "to=<*@example.org> <*@example.org>":
        return "le masquage écrit ici ne masque pas"
    return None


# --- LE CAPTEUR -----------------------------------------------------------------------------------
def implementations_awk():
    trouvees, chemins = [], set()
    for nom in AWK_EXERCES:
        chemin = shutil.which(nom)
        if chemin and os.path.realpath(chemin) not in chemins:
            chemins.add(os.path.realpath(chemin))
            trouvees.append((nom, chemin))
    return trouvees


def preparer(bac, chemin_awk):
    rep = {d: os.path.join(bac, d) for d in ("bin", "spool", "state", "journaux")}
    for d in rep.values():
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(os.path.join(rep["bin"], "awk")):
        os.symlink(chemin_awk, os.path.join(rep["bin"], "awk"))
    return rep


def jouer_capteur(rep, journaux, env_en_plus=None):
    """Un passage du capteur, mode fichier sauf mention. `journaux` : nom -> lignes (écrites sous `journaux/`).
    Rend `(événements, aveux, filtres de config)`."""
    for nom, lignes in journaux.items():
        with open(os.path.join(rep["journaux"], nom), "w", encoding="utf-8") as fh:
            fh.write("".join(l + "\n" for l in lignes))
    for nom in os.listdir(rep["spool"]):
        os.remove(os.path.join(rep["spool"], nom))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PLUME_", "LC_", "LANG"))}
    env.update(PATH=rep["bin"] + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
               PLUME_LIB=LIB, PLUME_SPOOL=rep["spool"], PLUME_STATE=rep["state"], PLUME_MAIL_SRC="file",
               PLUME_MAIL_LOG=os.path.join(rep["journaux"], "mail.log"),
               PLUME_MAIL_CLAMAV_LOG=os.path.join(rep["journaux"], "clamav.log"),
               PLUME_MAIL_FRESHCLAM_LOG=os.path.join(rep["journaux"], "freshclam.log"),
               PLUME_MAIL_MAX="1000", LC_ALL="C.UTF-8")
    for k, v in (env_en_plus or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    r = subprocess.run(["sh", CAPTEUR], env=env, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return None, None, None, f"le capteur a échoué (rc={r.returncode}) : {r.stderr.strip()[:300]}"
    evenements, aveux, filtres = [], [], None
    for nom in sorted(os.listdir(rep["spool"])):
        if nom.startswith(".") or not nom.endswith(".json"):
            continue
        try:
            doc = json.load(open(os.path.join(rep["spool"], nom), encoding="utf-8"))
        except (OSError, ValueError) as e:
            return None, None, None, f"enveloppe `{nom}` illisible comme JSON ({e})"
        for ev in doc.get("events") or []:
            f = ev.get("fields") or {}
            if ev.get("category") != "config":
                evenements.append(ev)
            elif f.get("type") == "collector-availability":
                aveux.append(ev)
            elif f.get("type") == "collection-reducing":
                filtres = f.get("filters") or {}
    return evenements, aveux, filtres, None


def passage_du_corpus(chemin_awk, entrees):
    fautes = []
    mail = [e["ligne"] for e in entrees if e["flux"] == "mail"]
    decalage = decalage_en_secondes(HORODATAGE_MAIL.match(mail[-1]).group(2))
    with tempfile.TemporaryDirectory(prefix="garde-mail-p1032f-") as bac:
        rep = preparer(bac, chemin_awk)
        ev, aveux, _, ko = jouer_capteur(rep, {"mail.log": mail,
                                               "clamav.log": [e["ligne"] for e in entrees if e["flux"] == "clamd"],
                                               "freshclam.log": [e["ligne"] for e in entrees if e["flux"] == "freshclam"]})
        if ko:
            return [ko]
        fautes += juger(entrees, ev, decalage)
        fautes += [f"aveu inattendu sur le corpus : `{a.get('message')}`" for a in aveux]
        # Le décalage POSÉ l'emporte sur celui de mail.log.
        clam = [e for e in entrees if e["flux"] != "mail"]
        for d in os.listdir(rep["state"]):
            os.remove(os.path.join(rep["state"], d))
        ev, aveux, _, ko = jouer_capteur(rep, {"mail.log": mail[-1:]}, {"PLUME_MAIL_CLAMAV_UTC_OFFSET": "-05:00"})
        if ko:
            return fautes + [ko]
        fautes += [f"(PLUME_MAIL_CLAMAV_UTC_OFFSET=-05:00) {f}"
                   for f in juger(clam + [e for e in entrees if e["ligne"] == mail[-1]], ev, decalage_en_secondes("-05:00"))]
    return fautes


# Le filigrane : un journal freshclam qui GRANDIT, trois passages, des lignes qui partagent leur seconde.
def _fc(hms, texte):
    return f"Thu Oct 15 {hms} 2026 -> ERROR: {texte}"
SEQUENCE = [_fc("01:00:00", "a1"), _fc("01:00:00", "a2"), _fc("01:00:00", "a3"),
            _fc("01:00:05", "b1"), _fc("01:00:05", "b2")]
SUITE = [_fc("01:00:05", "b3"), _fc("01:00:05", "b4"), _fc("01:00:09", "c1")]


def passage_du_filigrane(chemin_awk):
    fautes = []
    mail = ["2026-10-15T01:00:00.000000+00:00 mx1 opendmarc[1]: 9A: example.org pass"]
    with tempfile.TemporaryDirectory(prefix="garde-mail-filigrane-") as bac:
        rep = preparer(bac, chemin_awk)
        for etape, journal, attendus in (("1er passage", SEQUENCE, SEQUENCE),
                                         ("2e passage, journal grandi À LA MÊME SECONDE", SEQUENCE + SUITE, SUITE),
                                         ("3e passage, rien de neuf", SEQUENCE + SUITE, [])):
            ev, aveux, _, ko = jouer_capteur(rep, {"mail.log": mail, "clamav.log": [], "freshclam.log": journal})
            if ko:
                return [f"({etape}) {ko}"]
            vus = sorted(e["message"] for e in ev if (e.get("fields") or {}).get("service") == "freshclam")
            if vus != sorted(attendus):
                rejoues = sorted(set(vus) - set(attendus))
                sautes = sorted(set(attendus) - set(vus))
                fautes.append(f"filigrane ClamAV ({etape}) : {len(rejoues)} ligne(s) REJOUÉE(S) {rejoues[:3]}, "
                              f"{len(sautes)} ligne(s) SAUTÉE(S) {sautes[:3]}")
    return fautes


# Les trois modes. `docker` et `kubectl` sont simulés : ils lancent LOCALEMENT la commande que le capteur
# demande d'exécuter dans le conteneur, et consignent ce qui leur est demandé.
SIMULATEUR_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$BANC_TRACE"
[ "$1" = exec ] || exit 1
shift; [ "$1" = "$BANC_CONTENEUR" ] || exit 1
shift; exec "$@"
"""
SIMULATEUR_KUBECTL = """#!/bin/sh
printf '%s\\n' "$*" >> "$BANC_TRACE"
case "$*" in
  "-n $BANC_NS get pod -l $BANC_SEL -o name") echo pod/mail-0; exit 0 ;;
esac
[ "$1" = -n ] && [ "$2" = "$BANC_NS" ] && [ "$3" = exec ] && [ "$4" = pod/mail-0 ] && [ "$5" = -c ] || exit 1
shift 6; [ "$1" = -- ] && shift; exec "$@"
"""
SIMULATEUR_SH = """#!/bin/sh
printf '%s\\n' "$*" >> "$BANC_TRACE"
exec /bin/sh "$@"
"""


def passage_des_modes(chemin_awk, entrees):
    fautes = []
    mail = [e["ligne"] for e in entrees if e["corpus"] == "mail-opendmarc.corpus" and e["verdict"] != "aucun"][:1]
    clamd = [e["ligne"] for e in entrees if e["flux"] == "clamd" and e["verdict"] == "malware/infected"][:1]
    with tempfile.TemporaryDirectory(prefix="garde-mail-modes-") as bac:
        rep = preparer(bac, chemin_awk)
        trace = os.path.join(bac, "trace")
        for nom, texte in (("docker", SIMULATEUR_DOCKER), ("kubectl", SIMULATEUR_KUBECTL), ("sh", SIMULATEUR_SH)):
            p = os.path.join(rep["bin"], nom)
            open(p, "w").write(texte)
            os.chmod(p, 0o755)
        commun = {"BANC_TRACE": trace, "BANC_CONTENEUR": "mta", "BANC_NS": "messagerie", "BANC_SEL": "app=mta",
                  "PLUME_MAIL_CONTAINER": "mta", "PLUME_MAIL_NS": "messagerie", "PLUME_MAIL_SELECTOR": "app=mta"}
        defauts = {"PLUME_MAIL_CLAMAV_LOG": None, "PLUME_MAIL_FRESHCLAM_LOG": None}
        cas = [
            ("file, chemins par défaut", dict(commun, **defauts),
             ["lire /var/log/clamav/clamav.log", "lire /var/log/clamav/freshclam.log"]),
            ("docker, chemins par défaut", dict(commun, PLUME_MAIL_SRC="docker", **defauts),
             ["lire /var/log/mail/clamav.log", "lire /var/log/mail/freshclam.log"]),
            ("k3s, chemins par défaut", dict(commun, PLUME_MAIL_SRC="k3s", **defauts),
             ["lire /var/log/mail/clamav.log", "lire /var/log/mail/freshclam.log"]),
        ]
        for quoi, env, chemins in cas:
            if os.path.exists(trace):
                os.remove(trace)
            for d in os.listdir(rep["state"]):   # chaque mode repart d'un filigrane vierge
                os.remove(os.path.join(rep["state"], d))
            ev, aveux, filtres, ko = jouer_capteur(rep, {"mail.log": mail}, env)
            if ko:
                fautes.append(f"(mode {quoi}) {ko}")
                continue
            lu = open(trace).read() if os.path.exists(trace) else ""
            for c in chemins:
                if c not in lu:
                    fautes.append(f"(mode {quoi}) le journal ClamAV par défaut `{c.split()[1]}` n'a pas été demandé")
            hote_a_clamav = quoi.startswith("file") and any(os.path.exists(c.split()[1]) for c in chemins)
            if not hote_a_clamav:
                if aveux:
                    fautes.append(f"(mode {quoi}) un chemin PAR DÉFAUT absent a été avoué : `{aveux[0].get('message')}`")
                if (filtres or {}).get("clamav") != "clamd=absent freshclam=absent":
                    fautes.append(f"(mode {quoi}) enveloppe de config : clamav=`{(filtres or {}).get('clamav')}` au lieu de "
                                  "`clamd=absent freshclam=absent`")
            if not any(e.get("message") == mail[0] for e in ev):
                fautes.append(f"(mode {quoi}) mail.log n'a pas été lu par ce mode")
        # docker : un chemin POSÉ est lu par `docker exec` ; posé absent, il est AVOUÉ ; posé vide, coupé.
        clamav_hote = os.path.join(rep["journaux"], "clamav.log")
        ev, aveux, filtres, ko = jouer_capteur(rep, {"mail.log": mail, "clamav.log": clamd},
                                               dict(commun, PLUME_MAIL_SRC="docker", PLUME_MAIL_CLAMAV_LOG=clamav_hote,
                                                    PLUME_MAIL_FRESHCLAM_LOG=os.path.join(bac, "absent.log")))
        if ko:
            fautes.append(f"(docker, chemins posés) {ko}")
        else:
            if not any(e.get("message") == clamd[0] for e in ev):
                fautes.append("(docker, chemin posé) le journal clamd n'a pas été lu par `docker exec`")
            if not any("freshclam" in (a.get("message") or "") and (a.get("fields") or {}).get("collect_status") == "unavailable"
                       for a in aveux):
                fautes.append("(docker, chemin posé absent) l'absence d'un journal POSÉ n'est pas avouée")
            if (filtres or {}).get("clamav") != "clamd=lu freshclam=illisible":
                fautes.append(f"(docker, chemins posés) enveloppe de config : clamav=`{(filtres or {}).get('clamav')}`")
        ev, aveux, filtres, ko = jouer_capteur(rep, {"mail.log": mail},
                                               dict(commun, PLUME_MAIL_CLAMAV_LOG="", PLUME_MAIL_FRESHCLAM_LOG=""))
        if ko:
            fautes.append(f"(variables vides) {ko}")
        elif aveux or (filtres or {}).get("clamav") != "clamd=coupe freshclam=coupe":
            fautes.append(f"(variables vides) lecture non coupée : clamav=`{(filtres or {}).get('clamav')}`, {len(aveux)} aveu(x)")
    return fautes


def main():
    for f in (CAPTEUR, LIB):
        if not os.path.exists(f):
            refus(f"`{os.path.relpath(f, RACINE)}` introuvable")
    faute = epreuve_du_juge()
    if faute:
        refus(f"instrument INVALIDE — {faute}")
    entrees, fautes = lire_corpus()
    if fautes:
        refus("corpus hors forme : " + " ; ".join(fautes[:12]) + (f" (+{len(fautes) - 12})" if len(fautes) > 12 else ""))
    manques = [nom for nom, test in EXIGENCES if not any(test(e) for e in entrees)]
    if manques:
        refus("corpus sous son plancher : " + " ; ".join(manques))
    awks = implementations_awk()
    if not awks:
        refus(f"aucune implémentation d'awk parmi {AWK_EXERCES}")
    total = 0
    for nom, chemin in awks:
        defauts = passage_du_corpus(chemin, entrees) + passage_du_filigrane(chemin) + passage_des_modes(chemin, entrees)
        for f in defauts:
            print(f"::error file=collectors/mail.sh::{ETIQUETTE} ({nom}) : {f}")
        total += len(defauts)
    exerces = ", ".join(n for n, _ in awks)
    absents = ", ".join(n for n in AWK_EXERCES if n not in {n for n, _ in awks})
    if total:
        print(f"{ETIQUETTE} : {total} défaut(s) sur {len(entrees)} lignes (awk exercés : {exerces}).")
        sys.exit(1)
    par_corpus = ", ".join(f"{sum(1 for e in entrees if e['corpus'] == c)} {c}" for c in CORPUS)
    print(f"{ETIQUETTE} : le capteur mail LIVRÉ classe les {len(entrees)} lignes ({par_corpus}) comme attendu — "
          f"{len(EXIGENCES)} exigences de plancher, catégorie, sévérité, champs, horodatage et clé jugés, sortant masqué, "
          f"filigrane ClamAV sans rejeu ni saut sur trois passages, décalage posé et dérivé, trois modes et chemins "
          f"par défaut, rien d'inventé. Awk exercés : {exerces}" + (f" ; NON EXERCÉS (absents) : {absents}." if absents else "."))
    sys.exit(0)


if __name__ == "__main__":
    main()
