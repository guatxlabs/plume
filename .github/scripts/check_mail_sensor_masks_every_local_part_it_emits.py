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


def juger_corpus(evenements):
    fautes = []
    for ev in evenements:
        quoi = f"événement `{(ev.get('message') or '')[:110]}`"
        reste = partie_locale_restante(ev.get("message"))
        if reste:
            fautes.append(f"{quoi} : la partie locale `{reste}` subsiste dans le message")
        f = ev.get("fields") or {}
        for k in ("user", "sender", "rcpt"):
            if k in f and not FORME_MASQUEE.match(str(f[k])) and not (k == "sender" and originaire(ev)):
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


def jouer(chemin_awk, lignes):
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
        r = subprocess.run(["sh", CAPTEUR], env=env, capture_output=True, text=True, timeout=120)
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
    exerces = ", ".join(n for n, _ in awks)
    absents = ", ".join(n for n in AWK_EXERCES if n not in {n for n, _ in awks})
    if total:
        print(f"{ETIQUETTE} : {total} défaut(s) (awk exercés : {exerces}).")
        sys.exit(1)
    print(f"{ETIQUETTE} : le capteur mail LIVRÉ masque chaque partie locale qu'il émet — {len(FABRIQUEES)} lignes "
          f"fabriquées (une par famille, marqueurs absents de l'événement, champs masqués, étiquettes `clé=` "
          f"gardées, expéditeur d'une entrée originaire en clair dans `sender` seul, adossé à "
          f"`ex-mail-mass-outbound`) et {vus_corpus} événements des {len(corpus)} lignes de corpus livrées sans "
          f"partie locale restante. Awk exercés : {exerces}" + (f" ; NON EXERCÉS (absents) : {absents}." if absents else "."))
    sys.exit(0)


if __name__ == "__main__":
    main()
