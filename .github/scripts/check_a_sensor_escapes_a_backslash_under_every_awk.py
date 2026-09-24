#!/usr/bin/env python3
"""Un capteur qui rencontre un antislash publie une enveloppe JSON lisible et le texte EXACT, sous chaque awk — garde de CI (`P10.23-e`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Six capteurs construisent leurs événements JSON dans un programme awk et échappent leurs chaînes par
une fonction `jesc`. Cinq la recopiaient avec `gsub(/\\\\/,"\\\\\\\\",s)` : mawk 1.3.4 20200120 — l'awk
par défaut de Debian 11 et 12 et d'Ubuntu 22.04 — lit ce remplacement comme UN antislash et ne double
rien. Mesuré le 2026-09-24 sur `web.sh`, `minio.sh`, `dataaccess.sh`, `dataacl.sh`, `kube-rbac.sh`
joués dans un bac sous ce mawk : une seule valeur portant `\\0…`, un antislash final ou un guillemet
échappé rend l'enveloppe ENTIÈRE illisible (tout le passage perdu, filigrane avancé) ; `a\\b`,
`C:\\new\\table` ou `\\u0041` passent en JSON VALIDE mais décodé autrement (retour arrière, saut de
ligne, `A`) — une corruption silencieuse. mawk 1.3.3 (Debian 10) se comporte pareil ; gawk et mawk
20240123 et après doublent. Le sixième capteur (`mail.sh`) avait été corrigé seul (`P10.22-s`) : la
même fonction recopiée six fois s'était déjà divisée en deux variantes.

L'ÉCHAPPEMENT VIT DÉSORMAIS UNE FOIS : `_PLUME_AWK_ECHAPPEMENT_JSON`, défini dans `collectors/lib.sh`
et placé en tête de chaque programme awk qui l'appelle.

CE QUE LA GARDE FAIT
--------------------
1. FORME, sur tout `collectors/*.sh` (lib comprise) : aucun `sub`/`gsub` dont le remplacement porte
   quatre antislashs de suite (l'idiome qui diffère selon l'awk) ; `function jesc(` définie UNE fois,
   dans `lib.sh` ; tout capteur qui appelle `jesc(` y place `"$_PLUME_AWK_ECHAPPEMENT_JSON"` ; et
   l'ENSEMBLE des capteurs qui l'appellent est exactement celui que la garde joue (dans les deux sens :
   un capteur neuf qui échappe n'échappe pas à l'épreuve). Cette partie tient même sur un hôte dont
   le mawk double correctement — c'est le cas de l'image d'intégration.
2. LA FONCTION LIVRÉE, lue en sourçant `lib.sh` (jamais recopiée), jouée sous chaque awk sur une
   table de valeurs : le JSON décodé rend la valeur exacte, caractères de contrôle rendus en espace.
3. CHAQUE CAPTEUR, exécuté TEL QU'IL EST LIVRÉ dans un bac (spool, état, sources simulées : journal
   Traefik, `mc`, `find`, journal d'audit, `kubectl`, journal mail), sous chaque awk, avec les mêmes
   valeurs dans le champ que la source rend réellement : chaque enveloppe publiée est du JSON, aucune
   enveloppe cachée ne reste dans le spool, et chaque valeur ressort EXACTE, une fois.
Les valeurs d'un canal JSON (journal Traefik, `mc --json`) sont attendues sous la forme que le capteur
LIT : le texte encodé par la source, coupé au premier guillemet (le capteur ne décode pas le JSON
qu'il lit ; voir plus bas). Un guillemet dans un User-Agent y devient un antislash FINAL : c'est la
forme qui rendait l'enveloppe illisible, envoyable par n'importe quel client HTTP.

LE JUGE SE VALIDE AVANT DE JUGER
--------------------------------
Sur des spools FABRIQUÉS : le résultat exact ne doit rien accuser ; une enveloppe illisible, une
enveloppe cachée laissée, une valeur manquante, une valeur doublée, une valeur à l'antislash non
doublé (décodée `\\b` -> retour arrière) et un événement en trop doivent CHACUN être accusés. La
lecture de forme est éprouvée de même (l'idiome fautif est vu, `"&&"` et une suppression ne le sont
pas ; une seconde définition est vue). La table des valeurs a un PLANCHER nommé : un antislash
final, un échappement invalide, un échappement valide qui décoderait autrement, un guillemet ; et
chaque banc attend au moins cinq valeurs — sinon la garde refuse de conclure.

CE QUE LA GARDE NE TIENT PAS, DIT FRANCHEMENT
---------------------------------------------
Elle éprouve les capteurs du dépôt, pas ceux de l'hôte (famille de `P10.22-i`) ; la version d'awk de
l'hôte n'est pas connue du dépôt. Elle ne joue que les awk présents (gawk, mawk) : l'image
d'intégration n'a pas mawk 20200120, d'où la partie 1 (`P10.23-k`). Elle tient l'ÉCHAPPEMENT, pas la
LECTURE : `web.sh` et `minio.sh` lisent un texte JSON sans le décoder — une valeur y est stockée
encodée (`\\\\` pour un antislash, `\\u003c` pour `<`) et coupée à son premier guillemet échappé.
Les valeurs de `dataaccess.sh` que `auditd` écrit en hexadécimal (espace, guillemet, non-ASCII) n'y
sont pas décodées non plus. Un octet nul n'est pas éprouvé.
Sortie : 0 tenu · 1 défaut · 2 rien n'a été mesuré (lib ou capteur absent, commande absente, aucun
awk, juge ou lecture de forme non discriminants).
"""
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CAPTEURS = os.path.join(RACINE, "collectors")
LIB = os.path.join(CAPTEURS, "lib.sh")
VARIABLE = "_PLUME_AWK_ECHAPPEMENT_JSON"
ETIQUETTE = "P10.23-e"
AWK_EXERCES = ("gawk", "mawk")
COMMANDES_REQUISES = ("sh", "find", "grep", "sort", "tail", "mktemp", "cksum", "head", "cut")

# (nom, valeur BRUTE). Chaque valeur est un piège différent pour un antislash non doublé.
VALEURS = [
    ("antislash devant `b` (échappement JSON VALIDE : retour arrière)", "a\\b"),
    ("octal que Postfix journalise (`\\0` : échappement INVALIDE)", "\\026\\003\\001"),
    ("antislash final (échappe le guillemet fermant)", "fin\\"),
    ("chemin Windows (`\\n`, `\\t` : échappements VALIDES)", "C:\\new\\table"),
    ("`\\u0041` (échappement VALIDE : `A`)", "\\u0041"),
    ("deux antislashs", "x\\\\y"),
    ("antislash puis guillemet", "x\\\"y"),
    ("guillemet seul", "x\"y"),
]
# Contrôles : la fonction les rend en espace (JSON interdit un contrôle brut ; auditd joint ses clés
# multiples par \x1d). \x7f (DEL) est permis par JSON et passe tel quel.
VALEURS_DE_CONTROLE = [("SOH en tête", "\x01debut"), ("tabulation", "a\tb"), ("retour chariot", "cr\rfin"),
                       ("séparateur de groupe d'auditd", "cle1\x1dcle2"), ("DEL", "del\x7f")]
CONTROLE = re.compile(r"[\x01-\x1f]")
# LE PLANCHER, PIÈGE PAR PIÈGE : une table qui perd l'un d'eux rendrait un vert qui ne l'éprouve plus.
PIEGES_EXIGES = {
    "un antislash final": lambda v: v.endswith("\\") and not v.endswith("\\\\"),
    "un échappement JSON invalide (`\\0`)": lambda v: "\\0" in v,
    "un échappement JSON valide qui décoderait autrement (`\\b`, `\\n`, `\\u`)": lambda v: re.search(r"\\[bnu]", v),
    "un guillemet": lambda v: '"' in v,
}
ATTENDUS_MINIMUM_PAR_BANC = 5


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — la garde REFUSE DE CONCLURE, rien n'a été mesuré.")
    sys.exit(2)


def lu_depuis_json(v):
    """Ce qu'un capteur LIT d'une valeur écrite par un encodeur JSON (Go : Traefik, `mc`) : le texte
    encodé, jusqu'au premier guillemet — celui d'un `\\"` quand la valeur en porte un."""
    return json.dumps(v, ensure_ascii=False)[1:-1].split('"')[0]


# --- 1. LA FORME --------------------------------------------------------------------------------
# Un `sub`/`gsub` : son motif (/…/ ou "…"), puis son remplacement littéral.
APPEL_DE_REMPLACEMENT = re.compile(
    r'\bg?sub\(\s*(?:/(?:[^/\\\n]|\\.)*/|"(?:[^"\\\n]|\\.)*")\s*,\s*"((?:[^"\\\n]|\\.)*)"')
QUATRE_ANTISLASHS = "\\" * 4
DEFINITION = re.compile(r"\bfunction\s+jesc\s*\(")
APPEL = re.compile(r"(?<![A-Za-z0-9_])jesc\(")
INCLUSION = '"$' + VARIABLE + '"'


def idiomes_non_portables(texte):
    """Les numéros de ligne où un remplacement porte quatre antislashs de suite."""
    return [texte.count("\n", 0, m.start()) + 1 for m in APPEL_DE_REMPLACEMENT.finditer(texte)
            if QUATRE_ANTISLASHS in m.group(1)]


def lire_la_forme(fichiers):
    """`fichiers` : {nom: texte}. Rend `(fautes, appelants)`."""
    fautes, appelants, definitions = [], set(), []
    for nom, texte in sorted(fichiers.items()):
        for n in idiomes_non_portables(texte):
            fautes.append(f"collectors/{nom}:{n} : remplacement à quatre antislashs — mawk 1.3.4 20200120 "
                          "n'y double rien ; doubler un antislash s'écrit `\"&&\"`")
        definitions += [nom] * len(DEFINITION.findall(texte))
        sans_definition = DEFINITION.sub("", texte)
        if nom != "lib.sh" and APPEL.search(sans_definition):
            appelants.add(nom)
            if INCLUSION not in texte:
                fautes.append(f"collectors/{nom} : appelle `jesc(` sans placer {INCLUSION} en tête de son programme awk")
    if definitions != ["lib.sh"]:
        fautes.append(f"`function jesc(` doit être définie UNE fois, dans `lib.sh` ; définitions vues : "
                      f"{', '.join(definitions) or 'aucune'}")
    if VARIABLE not in fichiers.get("lib.sh", ""):
        fautes.append(f"`lib.sh` ne définit pas `{VARIABLE}`")
    return fautes, appelants


def epreuve_de_la_forme():
    fausse = 'function jesc(s){ gsub(/\\\\/,"\\\\\\\\",s); return s }\n'
    juste = 'function jesc(s){ gsub(/\\\\/,"&&",s); gsub(/"/,"\\\\\\"",s); gsub(/[\\\\"]/,"",m); return s }\n'
    if not idiomes_non_portables(fausse):
        return "l'idiome fautif n'est pas vu"
    if idiomes_non_portables(juste):
        return "`\"&&\"`, l'échappement du guillemet ou une suppression sont pris pour l'idiome fautif"
    lib = f"{VARIABLE}='{juste}'\n"
    appel = f'awk "${VARIABLE}"\'{{ print jesc($0) }}\'\n'
    if lire_la_forme({"lib.sh": lib, "a.sh": appel})[0]:
        return f"une forme CONFORME est accusée : {lire_la_forme({'lib.sh': lib, 'a.sh': appel})[0]}"
    ecarts = {
        "une seconde définition": {"lib.sh": lib, "a.sh": appel + juste},
        "un appel sans inclusion": {"lib.sh": lib, "a.sh": "awk '{ print jesc($0) }'\n"},
        "l'idiome fautif dans la lib": {"lib.sh": f"{VARIABLE}='{fausse}'\n", "a.sh": appel},
        "une lib sans la variable": {"lib.sh": juste, "a.sh": appel},
    }
    for nom, fichiers in ecarts.items():
        if not lire_la_forme(fichiers)[0]:
            return f"« {nom} » n'est pas accusé"
    if lire_la_forme({"lib.sh": lib, "a.sh": appel})[1] != {"a.sh"}:
        return "l'ensemble des appelants n'est pas lu"
    return None


# --- 2 et 3. LE JUGE -----------------------------------------------------------------------------
def juger(quoi, rc, stderr, spool, selection, champs, attendus):
    """`spool` : {nom de fichier: texte}. `attendus` : [{champ: valeur}]. Rend la liste des fautes."""
    if rc != 0:
        return [f"{quoi} : le capteur a échoué (rc={rc}) : {stderr.strip()[:300]}"]
    fautes, evenements = [], []
    for nom, texte in sorted(spool.items()):
        if nom.startswith("."):
            fautes.append(f"{quoi} : enveloppe cachée `{nom}` laissée dans le spool — jamais publiée")
            continue
        try:
            doc = json.loads(texte)
        except ValueError as e:
            fautes.append(f"{quoi} : enveloppe `{nom}` illisible comme JSON ({e}) — tout le passage est perdu")
            continue
        if doc.get("kind") == "events":
            evenements += [ev for ev in doc.get("events") or []
                           if ev.get("category") not in ("config", "health") and selection(ev)]
    if fautes:
        return fautes
    if len(evenements) != len(attendus):
        fautes.append(f"{quoi} : {len(evenements)} événement(s) au lieu de {len(attendus)}")
    for champ, lire in champs.items():
        vus = collections.Counter(lire(ev) for ev in evenements)
        voulus = collections.Counter(a[champ] for a in attendus)
        for v in sorted(voulus - vus, key=repr):
            fautes.append(f"{quoi} : `{champ}` = {v!r} attendu, absent (obtenus : "
                          f"{sorted((vus - voulus).elements(), key=repr)[:4]!r})")
        for v in sorted(vus - voulus, key=repr):
            if not (voulus - vus):
                fautes.append(f"{quoi} : `{champ}` = {v!r} en trop")
    return fautes


def epreuve_du_juge():
    champs = {"v": lambda ev: (ev.get("fields") or {}).get("v")}
    attendus = [{"v": "a\\b"}, {"v": "fin\\"}]

    def spool(*valeurs, brut=None):
        evs = ",".join('{"category":"x","fields":{"v":%s}}' % json.dumps(v) for v in valeurs)
        return {"x-1.json": brut if brut is not None else '{"kind":"events","events":[%s]}' % evs}
    exact = spool("a\\b", "fin\\")
    if juger("t", 0, "", exact, lambda ev: True, champs, attendus):
        return f"le juge accuse le résultat EXACT : {juger('t', 0, '', exact, lambda ev: True, champs, attendus)}"
    ecarts = {
        "une enveloppe illisible": spool(brut='{"kind":"events","events":[{"fields":{"v":"fin\\"}}]}'),
        "une enveloppe cachée laissée": dict(exact, **{".x.ABCDEF": ""}),
        "une valeur manquante": spool("a\\b"),
        "une valeur doublée": spool("a\\b", "fin\\", "fin\\"),
        "un antislash non doublé (décodé en retour arrière)": spool("a\b", "fin\\"),
        "un événement en trop": spool("a\\b", "fin\\", "z"),
        "un capteur en échec": None,
    }
    for nom, sp in ecarts.items():
        rc = 1 if sp is None else 0
        if not juger("t", rc, "", sp or {}, lambda ev: True, champs, attendus):
            return f"le juge n'accuse pas « {nom} »"
    return None


# --- LES BANCS : une source simulée par capteur ---------------------------------------------------
def _ecrire(chemin, texte, executable=False):
    with open(chemin, "w", encoding="utf-8", newline="") as fh:
        fh.write(texte)
    if executable:
        os.chmod(chemin, 0o755)


def banc_web(bac, env):
    lignes, attendus = [], []
    for i, (_, v) in enumerate(VALEURS):
        e = json.dumps(v, ensure_ascii=False)[1:-1]
        lignes.append(
            '{"ClientHost":"192.0.2.%d","DownstreamContentSize":12,"DownstreamStatus":200,"Duration":1500000,'
            '"RequestHost":"h%d.example.test","RequestMethod":"GET","RequestPath":"/q?x=%s","RequestProtocol":"HTTP/1.1",'
            '"RouterName":"site@kubernetescrd","StartUTC":"2026-09-23T19:40:%02d.123456789Z","level":"info",'
            '"request_User-Agent":"%s","time":"2026-09-23T21:40:%02d+02:00"}' % (10 + i, i, e, i, e, i))
        attendus.append({"ua": lu_depuis_json(v), "path": "/q?x=" + lu_depuis_json(v)})
    _ecrire(os.path.join(bac, "access.log"), "\n".join(lignes) + "\n")
    env.update(PLUME_WEB_SRC="file", PLUME_WEB_LOG=os.path.join(bac, "access.log"), PLUME_WEB_MAX="1000")
    return attendus


def banc_minio(bac, env):
    lignes, attendus = [], []
    for _, v in VALEURS:
        lignes.append('{"status":"success","accessKey":"%s","policyName":"readonly","userStatus":"enabled"}'
                      % json.dumps(v, ensure_ascii=False)[1:-1])
        attendus.append({"subject": lu_depuis_json(v)})
    _ecrire(os.path.join(bac, "mc-utilisateurs"), "\n".join(lignes) + "\n")
    _ecrire(os.path.join(bac, "bin", "mc"), """#!/bin/sh
# `mc` simulé : les quatre lectures du capteur, et rien d'autre.
case "$*" in
  "--json admin user list local") cat "$BANC_JESC/mc-utilisateurs" ;;
  "--json ls local") echo '{"status":"success","type":"folder","key":"seau/"}' ;;
  "--json admin info local") echo '{"status":"success","info":{"buckets":{"count":1},"objects":{"count":0},"versions":{"count":0}}}' ;;
  "anonymous get local/seau") echo 'Access permission for `local/seau` is `private`' ;;
  *) exit 1 ;;
esac
""", executable=True)
    env.update(PLUME_MINIO_ALIAS="local")
    return attendus


def banc_dataacl(bac, env):
    arbre = os.path.join(bac, "arbre")
    os.makedirs(arbre)
    attendus = []
    for _, v in VALEURS:
        os.mkdir(os.path.join(arbre, v))
        attendus.append({"path": os.path.join(arbre, v)})
    env.update(PLUME_ACL_PATHS=arbre, PLUME_ACL_DEPTH="1")
    return attendus


# auditd écrit un champ entre guillemets tant qu'il ne porte ni guillemet, ni espace, ni contrôle, ni
# octet hors ASCII (sinon en hexadécimal) : l'antislash y passe BRUT.
def banc_dataaccess(bac, env):
    lignes, attendus = [], []
    for i, (_, v) in enumerate(VALEURS):
        if '"' in v or " " in v:
            continue
        comm = v[:15]
        eid = "audit(1758650000.%03d:%d)" % (100 + i, 4000 + i)
        lignes.append(f"type=SYSCALL msg={eid}: arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc0000 "
                      f"a2=0 a3=0 items=1 ppid=1 pid={200 + i} auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
                      f'fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="{comm}" exe="/usr/bin/cat" '
                      f'subj=unconfined key="plume_data"')
        lignes.append(f'type=PATH msg={eid}: item=0 name="/srv/donnees/{v}" inode={10 + i} dev=fd:00 mode=0100644 '
                      f"ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0")
        attendus.append({"path": "/srv/donnees/" + v, "comm": comm})
    _ecrire(os.path.join(bac, "audit.log"), "\n".join(lignes) + "\n")
    env.update(PLUME_AUDIT_LOG=os.path.join(bac, "audit.log"))
    return attendus


# `kubectl get … -o jsonpath` écrit le texte BRUT. Un sujet `User`/`Group` est libre (nom venu d'un
# fournisseur d'identité : `CORP\alice`) ; seuls `|`, `;`, `=` — les séparateurs du capteur — en sont exclus.
def banc_kube_rbac(bac, env):
    fixtures = os.path.join(bac, "kube")
    os.makedirs(fixtures)
    _ecrire(os.path.join(fixtures, "clusterroles"),
            'lecteur-secrets=[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]\n')
    _ecrire(os.path.join(fixtures, "roles"), "")
    _ecrire(os.path.join(fixtures, "rolebindings"), "")
    lignes, attendus = [], []
    for i, (_, v) in enumerate(VALEURS):
        lignes.append(f"C|lien-{i}|view|User={v};")
        attendus.append({"subject": v})
    _ecrire(os.path.join(fixtures, "clusterrolebindings"), "\n".join(lignes) + "\n")
    _ecrire(os.path.join(bac, "bin", "kubectl"), """#!/bin/sh
# `kubectl` simulé : `version` répond, chaque `get` rend sa fixture.
case "$1" in
  version) echo "Client Version: v1.30.0" ;;
  get) cat "$BANC_JESC/kube/$2" ;;
  *) exit 1 ;;
esac
""", executable=True)
    return attendus


# Postfix écrit le texte de pré-salutation échappé (`\\ooo`) ; le capteur échappe la LIGNE entière.
def banc_mail(bac, env):
    lignes, attendus = [], []
    for i, (_, v) in enumerate(VALEURS):
        ligne = ("2026-09-23T19:50:%02d.000000+02:00 mailserver postfix/postscreen[3000]: "
                 "PREGREET 11 after 0 from [192.0.2.%d]:%d: %s" % (i, 10 + i, 40000 + i, v))
        lignes.append(ligne)
        attendus.append({"message": ligne})
    _ecrire(os.path.join(bac, "mail.log"), "\n".join(lignes) + "\n")
    env.update(PLUME_MAIL_SRC="file", PLUME_MAIL_LOG=os.path.join(bac, "mail.log"), PLUME_MAIL_MAX="1000")
    return attendus


def _champ(nom):
    return lambda ev: (ev.get("fields") or {}).get(nom)


# capteur -> (banc, sélection des événements jugés, champs jugés)
BANCS = {
    "web.sh": (banc_web, lambda ev: True, {"ua": _champ("ua"), "path": _champ("path")}),
    "minio.sh": (banc_minio, lambda ev: _champ("kind")(ev) == "user", {"subject": _champ("subject")}),
    "dataacl.sh": (banc_dataacl, lambda ev: "/arbre/" in (_champ("path")(ev) or ""), {"path": _champ("path")}),
    "dataaccess.sh": (banc_dataaccess, lambda ev: True, {"path": _champ("path"), "comm": _champ("comm")}),
    "kube-rbac.sh": (banc_kube_rbac, lambda ev: str(_champ("binding")(ev)).startswith("lien-"),
                     {"subject": _champ("subject")}),
    "mail.sh": (banc_mail, lambda ev: True, {"message": lambda ev: ev.get("message")}),
}


def jouer(capteur, chemin_awk, quoi):
    banc, selection, champs = BANCS[capteur]
    with tempfile.TemporaryDirectory(prefix="garde-jesc-") as bac:
        rep = {d: os.path.join(bac, d) for d in ("bin", "spool", "state")}
        for d in rep.values():
            os.makedirs(d)
        os.symlink(chemin_awk, os.path.join(rep["bin"], "awk"))
        env = {k: v for k, v in os.environ.items() if not k.startswith("PLUME_")}
        attendus = banc(bac, env)
        if len(attendus) < ATTENDUS_MINIMUM_PAR_BANC:
            refus(f"le banc de `{capteur}` n'attend que {len(attendus)} valeur(s) — sous le plancher de {ATTENDUS_MINIMUM_PAR_BANC}")
        env.update(PATH=rep["bin"] + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"), BANC_JESC=bac,
                   PLUME_LIB=LIB, PLUME_SPOOL=rep["spool"], PLUME_STATE=rep["state"])
        r = subprocess.run(["sh", os.path.join(CAPTEURS, capteur)], env=env, capture_output=True,
                           text=True, timeout=120)
        spool = {}
        for nom in os.listdir(rep["spool"]):
            # En octets, puis décodé SANS traduction de fin de ligne : un `\r` brut reste un `\r`.
            with open(os.path.join(rep["spool"], nom), "rb") as fh:
                spool[nom] = fh.read().decode("utf-8", "surrogateescape")
    return juger(quoi, r.returncode, r.stderr, spool, selection, champs, attendus)


def fonction_livree():
    """Le texte de `_PLUME_AWK_ECHAPPEMENT_JSON`, lu en SOURÇANT `lib.sh` — le code livré."""
    r = subprocess.run(["sh", "-c", '. "$1" && printf "%s" "${' + VARIABLE + ':-}"', "sh", LIB],
                       capture_output=True, text=True, timeout=60)
    return r.stdout if r.returncode == 0 else ""


def epreuve_de_la_fonction(chemin_awk, fonction, quoi):
    table = VALEURS + VALEURS_DE_CONTROLE
    with tempfile.TemporaryDirectory(prefix="garde-jesc-fonction-") as bac:
        cas = os.path.join(bac, "cas")
        _ecrire(cas, "".join(v + "\n" for _, v in table))
        r = subprocess.run([chemin_awk, fonction + '\n{ print "{\\"v\\":\\"" jesc($0) "\\"}" }', cas],
                           capture_output=True, timeout=60)
    if r.returncode != 0:
        return [f"{quoi} : la fonction livrée ne tourne pas : {r.stderr.decode('utf-8', 'replace').strip()[:300]}"]
    fautes = []
    # En octets : un contrôle brut laissé par la fonction ne doit pas être traduit en fin de ligne.
    for (nom, v), ligne in zip(table, r.stdout.decode("utf-8", "surrogateescape").split("\n")):
        voulu = CONTROLE.sub(" ", v)
        try:
            obtenu = json.loads(ligne)["v"]
        except (ValueError, KeyError) as e:
            fautes.append(f"{quoi} : {nom} {v!r} -> {ligne!r}, illisible comme JSON ({e})")
            continue
        if obtenu != voulu:
            fautes.append(f"{quoi} : {nom} {v!r} -> décodé {obtenu!r} au lieu de {voulu!r}")
    return fautes


def implementations_awk():
    trouvees, chemins = [], set()
    for nom in AWK_EXERCES:
        chemin = shutil.which(nom)
        if chemin and os.path.realpath(chemin) not in chemins:
            chemins.add(os.path.realpath(chemin))
            r = subprocess.run([chemin, "-W", "version"], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            version = (r.stdout or r.stderr).strip().split("\n")[0].split(",")[0][:30] or nom
            trouvees.append((version, chemin))
    return trouvees


def main():
    if not os.path.exists(LIB):
        refus("`collectors/lib.sh` introuvable")
    for c in COMMANDES_REQUISES:
        if shutil.which(c) is None:
            refus(f"commande `{c}` absente")
    for epreuve, quoi in ((epreuve_du_juge, "juge"), (epreuve_de_la_forme, "lecture de forme")):
        faute = epreuve()
        if faute:
            refus(f"instrument INVALIDE ({quoi}) — {faute}")
    fichiers = {}
    for nom in sorted(os.listdir(CAPTEURS)):
        if nom.endswith(".sh"):
            with open(os.path.join(CAPTEURS, nom), encoding="utf-8") as fh:
                fichiers[nom] = fh.read()
    for capteur in BANCS:
        if capteur not in fichiers:
            refus(f"`collectors/{capteur}` introuvable")
    manques = [nom for nom, vrai in PIEGES_EXIGES.items() if not any(vrai(v) for _, v in VALEURS)]
    if manques:
        refus("table des valeurs sous son plancher : " + " ; ".join(manques))
    fautes, appelants = lire_la_forme(fichiers)
    for nom in sorted(appelants - set(BANCS)):
        fautes.append(f"collectors/{nom} échappe par `jesc` mais n'est pas joué par cette garde — ajouter son banc")
    for nom in sorted(set(BANCS) - appelants):
        fautes.append(f"collectors/{nom} est joué mais n'appelle plus `jesc` — retirer son banc ou le dire")
    awks = implementations_awk()
    if not awks:
        refus(f"aucune implémentation d'awk parmi {AWK_EXERCES}")
    fonction = fonction_livree()
    if not fonction:
        fautes.append(f"`{VARIABLE}` introuvable en sourçant `lib.sh` : la fonction livrée n'est pas jouée")
    for version, chemin in awks:
        if fonction:
            fautes += epreuve_de_la_fonction(chemin, fonction, f"fonction ({version})")
        for capteur in BANCS:
            f = jouer(capteur, chemin, f"{capteur} ({version})")
            print(f"{ETIQUETTE} : {capteur:<14} {version:<22} "
                  + ("tenu" if not f else f"{len(f)} défaut(s) — {f[0][:160]}"))
            fautes += f
    for f in fautes:
        print(f"::error::{ETIQUETTE} : {f}")
    exerces = ", ".join(v for v, _ in awks)
    if fautes:
        print(f"{ETIQUETTE} : {len(fautes)} défaut(s) ; awk exercés : {exerces}.")
        sys.exit(1)
    print(f"{ETIQUETTE} : l'échappement JSON vit une fois (`{VARIABLE}`, lib.sh), sans l'idiome à quatre "
          f"antislashs ; les {len(BANCS)} capteurs qui l'appellent publient une enveloppe lisible et rendent "
          f"les {len(VALEURS)} valeurs à antislash exactes, sous : {exerces}.")
    sys.exit(0)


if __name__ == "__main__":
    main()
