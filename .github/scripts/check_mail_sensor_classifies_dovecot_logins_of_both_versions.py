#!/usr/bin/env python3
"""Le capteur mail classe les connexions Dovecot 2.3 ET 2.4, et « Login aborted » n'est jamais un succès — garde de CI (`P10.22-j`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Mesuré le 2026-09-23 sur un pod d'essai docker-mailserver 16.0.1 (Dovecot 2.4.1) : une connexion
réussie s'y journalise `imap-login: Logged in: user=<…>`, là où la production (2.3.19.1) écrit
`imap-login: Login: user=<…>`. `collectors/mail.sh` ne reconnaissait que `Login:` : après la montée
du serveur mail, plus AUCUNE connexion réussie n'aurait été émise — pas d'erreur, pas de battement
manquant, seulement une catégorie qui se vide. Aucun témoin n'exécutait ce capteur : sa
classification n'était tenue par rien.

CE QUE LA GARDE FAIT
--------------------
Elle lit le corpus `collectors/mail-connexions-dovecot.corpus` (lignes 2.3 et 2.4, chacune avec son
verdict attendu et la PROVENANCE de sa forme), écrit ces lignes dans un journal fabriqué, exécute le
capteur TEL QU'IL EST LIVRÉ en mode fichier (`PLUME_MAIL_SRC=file`) dans un bac — spool, état et
journal à lui — puis relit l'enveloppe publiée et juge CHAQUE ligne :
  * `succes` -> exactement un événement `auth`/`success`, avec le `user` et le `src_ip` attendus ;
  * `echec`  -> exactement un événement `auth`/`failure`, idem ;
  * `aucun`  -> aucun événement ;
  * et aucun événement dont le message n'est pas une ligne du corpus (rien d'inventé).
Le capteur est joué sous CHAQUE implémentation d'awk présente parmi `gawk` et `mawk` (l'hôte
Debian/Ubuntu livre `mawk` par défaut) : la classification est un programme awk, et un motif
qu'une implémentation lit autrement est un capteur qui ne classe pas pareil selon l'hôte.

LE CORPUS SE VALIDE AVANT DE SERVIR
-----------------------------------
Un corpus qui perd sa matière rend un vert vide. Avant toute exécution : chaque ligne a cinq
colonnes, un verdict et une provenance du vocabulaire fermé, un horodatage ISO en tête, un `user`
et une `rip=` qui concordent avec les colonnes attendues ; aucune ligne portant « Login aborted »
n'est déclarée `succes` (le corpus ne peut pas légitimer le défaut qu'il garde) ; toute adresse
est de documentation (RFC 5737) ou de bouclage, tout utilisateur est vide, sous `example.test`, ou
sur une ligne `fabriquee-*`. PLANCHER : pour chaque version, au moins un `succes`, un `echec` et un
`aucun` ; les lignes MESURÉES du constat (succès et échec 2.4.1, succès 2.3.19.1) ; un succès 2.4
par service de connexion (imap, pop3, submission, managesieve) ; un témoin d'ancrage par version.

LE JUGE SE VALIDE AUSSI
-----------------------
Avant de juger le capteur, le juge est éprouvé sur des événements FABRIQUÉS : le résultat exact ne
doit rien accuser ; un succès manquant, un succès rendu en échec, un événement pour une ligne
`aucun`, un `user` faux et un événement inventé doivent CHACUN être accusés.

CE QUE LA GARDE NE TIENT PAS, DIT FRANCHEMENT
---------------------------------------------
Elle éprouve la CLASSIFICATION du capteur livré, pas ce qui tourne sur l'hôte : un capteur corrigé
ici et jamais installé ne classe rien (famille de `P10.22-i`). Les formes `sources-*` sont dérivées
des sources, pas relevées ; seules les lignes `mesuree-*` l'ont été. Une adresse IPv6 en `rip=`
n'est pas dans le corpus : le capteur n'en extrait qu'un préfixe, défaut antérieur à cette clé et
hors de son périmètre.
Sortie : 0 tenu · 1 défaut · 2 rien n'a été mesuré (capteur, bibliothèque ou corpus absent, corpus
invalide ou sous son plancher, juge non discriminant, aucun awk, capteur en échec, spool illisible).
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
CORPUS = os.path.join(RACINE, "collectors", "mail-connexions-dovecot.corpus")
ETIQUETTE = "P10.22-j"

ACTION_DU_VERDICT = {"succes": "success", "echec": "failure", "aucun": None}
VERSION_DE_LA_PROVENANCE = {
    "mesuree-2.4.1": "2.4", "sources-2.4.1": "2.4", "fabriquee-2.4": "2.4",
    "mesuree-2.3.19.1": "2.3", "enonce-2.3": "2.3", "sources-2.3.19.1": "2.3", "fabriquee-2.3": "2.3",
}
SERVICES_DE_CONNEXION = ("imap", "pop3", "submission", "managesieve")
AWK_EXERCES = ("gawk", "mawk")
PLAGES_DE_DOCUMENTATION = [ipaddress.ip_network(n) for n in
                           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8")]
HORODATAGE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?[+-]\d\d:\d\d ")
QUADRUPLET = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])")
UTILISATEUR = re.compile(r"user=<([^>]*)>")
RIP = re.compile(r"rip=([0-9.]+)")
SERVICE = re.compile(r" dovecot(?:\[\d+\])?: ([a-z0-9]+)-login: ")


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — la garde REFUSE DE CONCLURE, rien n'a été mesuré.")
    sys.exit(2)


# --- LE CORPUS -----------------------------------------------------------------------------------
def lire_corpus():
    try:
        brut = open(CORPUS, encoding="utf-8").read().splitlines()
    except OSError as e:
        refus(f"corpus `{os.path.relpath(CORPUS, RACINE)}` illisible ({e})")
    entrees, vues, fautes = [], set(), []
    for n, texte in enumerate(brut, 1):
        if not texte.strip() or texte.startswith("#"):
            continue
        colonnes = texte.split("\t")
        if len(colonnes) != 5:
            fautes.append(f"ligne {n} : {len(colonnes)} colonnes au lieu de 5")
            continue
        verdict, user, ip, provenance, ligne = colonnes
        if verdict not in ACTION_DU_VERDICT:
            fautes.append(f"ligne {n} : verdict `{verdict}` hors vocabulaire {sorted(ACTION_DU_VERDICT)}")
        if provenance not in VERSION_DE_LA_PROVENANCE:
            fautes.append(f"ligne {n} : provenance `{provenance}` hors vocabulaire")
        if not HORODATAGE.match(ligne):
            fautes.append(f"ligne {n} : pas d'horodatage ISO avec décalage en tête — le capteur l'ignorerait")
        if ligne in vues:
            fautes.append(f"ligne {n} : ligne en double")
        vues.add(ligne)
        if verdict == "succes" and "Login aborted" in ligne:
            fautes.append(f"ligne {n} : une ligne « Login aborted » déclarée `succes` — le corpus légitimerait le défaut qu'il garde")
        u = UTILISATEUR.search(ligne)
        u_ligne = u.group(1) if u else ""
        if (user if user != "-" else "") != u_ligne:
            fautes.append(f"ligne {n} : `user` attendu `{user}` ≠ `user=<{u_ligne}>` de la ligne")
        if u_ligne and not u_ligne.endswith("@example.test") and not provenance.startswith("fabriquee-"):
            fautes.append(f"ligne {n} : utilisateur `{u_ligne}` hors de `example.test`")
        r = RIP.search(ligne)
        if verdict != "aucun" and (r is None or r.group(1) != ip):
            fautes.append(f"ligne {n} : `src_ip` attendu `{ip}` ≠ `rip=` de la ligne")
        for q in QUADRUPLET.findall(ligne):
            try:
                adresse = ipaddress.ip_address(q)
            except ValueError:
                fautes.append(f"ligne {n} : `{q}` n'est pas une adresse")
                continue
            if not any(adresse in p for p in PLAGES_DE_DOCUMENTATION):
                fautes.append(f"ligne {n} : adresse `{q}` hors des plages de documentation — une vraie adresse n'a rien à faire ici")
        s = SERVICE.search(ligne)
        entrees.append(dict(n=n, verdict=verdict, user=(user if user != "-" else ""), ip=ip,
                            provenance=provenance, version=VERSION_DE_LA_PROVENANCE.get(provenance),
                            service=(s.group(1) if s else None), ligne=ligne))
    if fautes:
        for f in fautes:
            print(f"::error file=collectors/mail-connexions-dovecot.corpus::{ETIQUETTE} : {f}")
        refus(f"corpus invalide ({len(fautes)} faute(s))")
    plancher(entrees)
    return entrees


def plancher(entrees):
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
        if not any(e["version"] == "2.4" and e["verdict"] == "succes" and e["service"] == service for e in entrees):
            manques.append(f"aucun succès 2.4 de `{service}-login`")
    if not any("Login aborted" in e["ligne"] and e["verdict"] != "succes" for e in entrees):
        manques.append("aucune ligne « Login aborted » : la propriété centrale n'est pas exercée")
    if manques:
        refus("corpus sous son plancher : " + " ; ".join(manques))


# --- LE JUGE -------------------------------------------------------------------------------------
def juger(entrees, evenements):
    fautes = []
    par_message = {}
    for ev in evenements:
        par_message.setdefault(ev.get("message"), []).append(ev)
    for e in entrees:
        vus = par_message.pop(e["ligne"], [])
        attendue = ACTION_DU_VERDICT[e["verdict"]]
        quoi = f"ligne {e['n']} ({e['provenance']}, attendu `{e['verdict']}`)"
        if attendue is None:
            if vus:
                fautes.append(f"{quoi} : {len(vus)} événement(s) émis, action `{vus[0].get('fields', {}).get('action')}`")
            continue
        if len(vus) != 1:
            fautes.append(f"{quoi} : {len(vus)} événement(s) au lieu d'un — ligne non classée")
            continue
        ev = vus[0]
        champs = ev.get("fields") or {}
        if ev.get("category") != "auth" or champs.get("action") != attendue:
            fautes.append(f"{quoi} : classée `{ev.get('category')}`/`{champs.get('action')}` au lieu de `auth`/`{attendue}`")
        if champs.get("user") != e["user"]:
            fautes.append(f"{quoi} : `user` = `{champs.get('user')}` au lieu de `{e['user']}`")
        if ev.get("src_ip") != e["ip"] or champs.get("src_ip") != e["ip"]:
            fautes.append(f"{quoi} : `src_ip` = `{ev.get('src_ip')}`/`{champs.get('src_ip')}` au lieu de `{e['ip']}`")
    for message, vus in par_message.items():
        fautes.append(f"{len(vus)} événement(s) pour un message absent du corpus : `{str(message)[:120]}`")
    return fautes


def epreuve_du_juge():
    """Témoins sur des événements FABRIQUÉS : le juge doit se taire sur l'exact et accuser chaque écart."""
    def ev(ligne, action, user, ip):
        return {"source": "mail", "category": "auth", "src_ip": ip, "message": ligne,
                "fields": {"action": action, "user": user, "src_ip": ip}}
    corpus = [
        dict(n=1, verdict="succes", user="a@example.test", ip="192.0.2.1", provenance="x", ligne="L1"),
        dict(n=2, verdict="echec", user="b@example.test", ip="192.0.2.2", provenance="x", ligne="L2"),
        dict(n=3, verdict="aucun", user="", ip="-", provenance="x", ligne="L3"),
    ]
    exact = [ev("L1", "success", "a@example.test", "192.0.2.1"), ev("L2", "failure", "b@example.test", "192.0.2.2")]
    if juger(corpus, exact):
        return f"le juge accuse le résultat EXACT : {juger(corpus, exact)}"
    ecarts = {
        "succès manquant": exact[1:],
        "succès rendu en échec": [ev("L1", "failure", "a@example.test", "192.0.2.1"), exact[1]],
        "événement pour une ligne `aucun`": exact + [ev("L3", "failure", "", "192.0.2.3")],
        "`user` faux": [ev("L1", "success", "z@example.test", "192.0.2.1"), exact[1]],
        "événement inventé": exact + [ev("L9", "success", "a@example.test", "192.0.2.1")],
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
                refus(f"enveloppe `{nom}` illisible ({e})")
            if doc.get("kind") != "events":
                continue
            enveloppes += 1
            evenements += [ev for ev in doc.get("events") or [] if ev.get("category") != "config"]
        if enveloppes == 0:
            refus(f"le capteur n'a déposé aucune enveloppe d'événements sous `{chemin_awk}`")
        return evenements


def main():
    for f in (CAPTEUR, LIB, CORPUS):
        if not os.path.exists(f):
            refus(f"`{os.path.relpath(f, RACINE)}` introuvable")
    if shutil.which("sh") is None:
        refus("aucun `sh`")
    faute = epreuve_du_juge()
    if faute:
        refus(f"instrument INVALIDE — {faute}")
    entrees = lire_corpus()
    awks = implementations_awk()
    if not awks:
        refus(f"aucune implémentation d'awk parmi {AWK_EXERCES}")
    total = 0
    for nom, chemin in awks:
        fautes = juger(entrees, lancer(chemin, entrees))
        for f in fautes:
            print(f"::error file=collectors/mail.sh::{ETIQUETTE} ({nom}) : {f}")
        total += len(fautes)
    exerces = ", ".join(n for n, _ in awks)
    absents = ", ".join(n for n in AWK_EXERCES if n not in {n for n, _ in awks})
    if total:
        print(f"{ETIQUETTE} : {total} défaut(s) de classification sur {len(entrees)} lignes Dovecot (awk exercés : {exerces}).")
        sys.exit(1)
    par_version = {v: sum(1 for e in entrees if e["version"] == v) for v in ("2.3", "2.4")}
    print(f"{ETIQUETTE} : le capteur mail LIVRÉ classe les {len(entrees)} lignes Dovecot du corpus "
          f"({par_version['2.4']} en 2.4, {par_version['2.3']} en 2.3) comme attendu — succès `Login:` et "
          f"`Logged in:` lus à l'en-tête du message, « Login aborted » jamais succès, `user`/`src_ip` extraits, "
          f"rien d'inventé. Awk exercés : {exerces}" + (f" ; NON EXERCÉS (absents) : {absents}." if absents else "."))
    sys.exit(0)


if __name__ == "__main__":
    main()
