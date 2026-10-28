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
Les valeurs d'un canal JSON (journal Traefik, `mc --json`) sont attendues DÉCODÉES (`P10.23-x`) : la
valeur que la source a encodée, exacte. Elles y sont écrites deux fois, comme Go les écrit — texte brut
hors échappement, et tout en `\\uXXXX` avec `<`, `>`, `&` échappés (ce que fait `encoding/json`) —, plus
`\\/`, une paire de substitution et U+2028 (`VALEURS_ENCODEES`).
4. LE DÉCODEUR LIVRÉ (`_PLUME_AWK_DECODAGE_JSON`, `jstr`), lu en sourçant `lib.sh`, joué sous chaque awk
   sur chaque valeur des deux encodages : `jesc(jstr(…))` rend la valeur exacte. Et, par la forme : `jstr`
   définie une fois, dans `lib.sh` ; tout appelant inclut la variable ; `web.sh` et `minio.sh` en sont.
   Plus `CAS_DU_DECODEUR` (`\\n` `\\b` `\\f`, NUL, substituts isolés, échappements invalides gardés, chaîne
   tronquée) et un COÛT borné : 600000 échappements décodés sous 10 s (la première version était quadratique).
   Dans `web.sh`, la méthode et le protocole portent les valeurs aussi : décodés, ils doivent être échappés.

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
LECTURE des autres capteurs : seuls `web.sh` et `minio.sh` lisent un texte JSON, et c'est par `jstr`
(`P10.23-x`) ; la garde ne voit pas un capteur neuf qui lirait du JSON par une expression régulière. Les noms que `auditd` écrit en hexadécimal (espace, guillemet, contrôle, non-ASCII), eux,
SONT décodés par `dataaccess.sh` (`P10.23-z`) : son banc les écrit comme `auditd` et rejoue en plus
`collectors/dataaccess-hex.corpus` (octet nul, contrôles 0x09/0x1B/0x1F, DEL, octet non UTF-8, bornes
de l'UTF-8 strict — surlongs E0/F0, substitut ED, F4 au-delà de 8F, tête F5, octet de suite invalide, plus
petits et plus grands points de chaque longueur —, longueur impaire, valeur entre guillemets) ; il exige le
chemin DÉCODÉ dans `path`, `comm` ET le `message`. L'hypothèse du décodage — une valeur NUE et hexadécimale est un
encodage du noyau — n'est pas éprouvable ici : un journal écrit par un autre que le noyau peut la démentir.
Un octet nul n'est éprouvé que par ce corpus, pas dans les autres capteurs.
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
VARIABLE_DECODAGE = "_PLUME_AWK_DECODAGE_JSON"
LECTEURS_JSON_EXIGES = {"web.sh", "minio.sh"}   # P10.23-x : les capteurs qui lisent un texte JSON
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
# Contrôles : la fonction les rend en espace (JSON interdit un contrôle brut ; 0x1D sépare les champs
# du format ENRICHED d'auditd, le noyau joint les clés multiples par 0x01). \x7f (DEL) est permis par JSON et passe tel quel.
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

# P10.23-x — valeurs que Go (`encoding/json` : Traefik, `mc`) écrit ÉCHAPPÉES même sans antislash ni guillemet.
VALEURS_ENCODEES = [
    ("balise (`\\u003c` `\\u003e` `\\u0026`)", "<script>alert(1)&x</script>"),
    ("non-ASCII deux et trois octets", "été 日本"),
    ("hors du plan de base (paire de substitution)", "\U0001F600 fin"),
    ("U+2028 (que Go échappe)", "a\u2028b"),
    ("barre oblique (`\\/`)", "a/b/c"),
]

# P10.23-x — ce que le décodeur rend pour ce que les tables ci-dessus n'écrivent pas : (nom, LIGNE entière, attendu
# après `jesc`). Un contrôle décodé ressort en espace (`jesc`) ; il doit être DÉCODÉ (un `\n` gardé ressortirait
# `\n`). Un substitut isolé rend U+FFFD ; un échappement invalide est gardé tel quel ; une chaîne sans guillemet
# fermant rend ce qui a été lu.
CAS_DU_DECODEUR = [
    ("saut de ligne `\\n`", '{"a":1,"k":"a\\nb","z":"fin"}', "a b"),
    ("retour arrière `\\b`", '{"a":1,"k":"a\\bb","z":"fin"}', "a b"),
    ("saut de page `\\f`", '{"a":1,"k":"a\\fb","z":"fin"}', "a b"),
    ("NUL `\\u0000` (rendu en espace)", '{"a":1,"k":"a\\u0000b","z":"fin"}', "a b"),
    ("substitut haut isolé", '{"a":1,"k":"a\\ud800b","z":"fin"}', "a\ufffdb"),
    ("substitut haut suivi d'un non-substitut", '{"a":1,"k":"\\ud83d\\u0041","z":"fin"}', "\ufffdA"),
    ("substitut bas isolé", '{"a":1,"k":"a\\udc00b","z":"fin"}', "a\ufffdb"),
    ("échappement invalide `\\q` gardé", '{"a":1,"k":"a\\qb","z":"fin"}', "a\\qb"),
    ("`\\uZZZZ` invalide gardé", '{"a":1,"k":"a\\uZZZZb","z":"fin"}', "a\\uZZZZb"),
    ("`\\u` court devant le guillemet", '{"a":1,"k":"a\\u00","z":"fin"}', "a\\u00"),
    ("chaîne tronquée (pas de guillemet fermant)", '{"a":1,"k":"tronque\\u0041', "tronqueA"),
    ("chaîne tronquée sur un antislash", '{"a":1,"k":"fin\\', "fin\\"),
    ("clé absente", '{"a":1,"z":"fin"}', ""),
    ("antislash échappé puis guillemet fermant", '{"a":1,"k":"x\\\\","z":"fin"}', "x\\"),
    # Bords épinglés après vérification (un mutant de chacun laissait la garde verte) : chemin rapide d'une
    # chaîne tronquée SANS antislash, paire de substituts NON contiguë, deux substituts bas, bornes de
    # l'UTF-8 à deux et trois octets (U+0400, U+07FF, U+0800 : pas de forme surlongue), hexadécimal en
    # majuscules, clé dont le nom finit comme celle qu'on cherche.
    ("chaîne tronquée sans antislash (chemin rapide)", '{"a":1,"k":"tronque', "tronque"),
    ("paire de substituts séparée par un caractère", '{"a":1,"k":"\\ud83dX\\ude00","z":"fin"}', "\ufffdX\ufffd"),
    ("deux substituts bas", '{"a":1,"k":"\\udc00\\udc00","z":"fin"}', "\ufffd\ufffd"),
    ("bornes UTF-8 deux et trois octets", '{"a":1,"k":"\\u0400\\u07ff\\u0800","z":"fin"}', "\u0400\u07ff\u0800"),
    ("hexadécimal en majuscules", '{"a":1,"k":"\\u003C","z":"fin"}', "<"),
    ("clé au nom suffixe de la cherchée", '{"xk":"faux","k":"bon"}', "bon"),
]
# P10.23-x — LE COÛT : la première version recopiait le reste de la ligne et la sortie à chaque échappement,
# un temps QUADRATIQUE (64000 `\u003c` : 2,3 s sous mawk ; tout client choisit son chemin). Une valeur de
# ECHAPPEMENTS_DU_COUT échappements doit être décodée sous BUDGET_DU_COUT_S secondes. Mesuré sur le VPS de
# compilation (2026-10-27) : découpe + jointure par paires 1,7 s (mawk) et 2,9 s (gawk 5.2.1) ; la même découpe
# jointe par `o = o …` ~36 s sous mawk (qui n'a pas l'ajout en place de gawk), la première version au-delà.
ECHAPPEMENTS_DU_COUT = 600000
BUDGET_DU_COUT_S = 10


def encode_comme_go(v, ascii_seul):
    """Le texte JSON (sans guillemets) qu'un encodeur écrit pour `v` : brut hors échappement, ou tout en
    `\\uXXXX` avec `<`, `>`, `&` échappés comme `encoding/json` et `/` en `\\/` (permis, écrit par d'autres)."""
    e = json.dumps(v, ensure_ascii=ascii_seul)[1:-1]
    if ascii_seul:
        e = e.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("/", "\\/")
    return e


def valeurs_encodees():
    """[(nom, texte encodé, valeur attendue)] : chaque valeur des deux tables, sous les deux encodages."""
    return [(f"{nom} ({'ascii' if a else 'brut'})", encode_comme_go(v, a), v)
            for nom, v in VALEURS + VALEURS_ENCODEES for a in (False, True)]


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — la garde REFUSE DE CONCLURE, rien n'a été mesuré.")
    sys.exit(2)


# --- 1. LA FORME --------------------------------------------------------------------------------
# Un `sub`/`gsub` : son motif (/…/ ou "…"), puis son remplacement littéral.
APPEL_DE_REMPLACEMENT = re.compile(
    r'\bg?sub\(\s*(?:/(?:[^/\\\n]|\\.)*/|"(?:[^"\\\n]|\\.)*")\s*,\s*"((?:[^"\\\n]|\\.)*)"')
QUATRE_ANTISLASHS = "\\" * 4
DEFINITION = re.compile(r"\bfunction\s+jesc\s*\(")
APPEL = re.compile(r"(?<![A-Za-z0-9_])jesc\(")
INCLUSION = '"$' + VARIABLE + '"'
DEFINITION_DECODAGE = re.compile(r"\bfunction\s+jstr\s*\(")
APPEL_DECODAGE = re.compile(r"(?<![A-Za-z0-9_])jstr\(")
INCLUSION_DECODAGE = '"$' + VARIABLE_DECODAGE + '"'


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
    # P10.23-x — le décodeur, même règle : une définition, dans lib.sh ; tout appelant l'inclut ; les lecteurs
    # de JSON en sont.
    lecteurs, defs = set(), []
    for nom, texte in sorted(fichiers.items()):
        defs += [nom] * len(DEFINITION_DECODAGE.findall(texte))
        if nom != "lib.sh" and APPEL_DECODAGE.search(DEFINITION_DECODAGE.sub("", texte)):
            lecteurs.add(nom)
            if INCLUSION_DECODAGE not in texte:
                fautes.append(f"collectors/{nom} : appelle `jstr(` sans placer {INCLUSION_DECODAGE} en tête de son programme awk")
    if defs != ["lib.sh"]:
        fautes.append(f"`function jstr(` doit être définie UNE fois, dans `lib.sh` ; définitions vues : {', '.join(defs) or 'aucune'}")
    for nom in sorted(LECTEURS_JSON_EXIGES - lecteurs):
        fautes.append(f"collectors/{nom} lit un texte JSON sans `jstr` : une valeur y reste encodée et coupée "
                      "à son premier guillemet échappé (P10.23-x)")
    return fautes, appelants


def epreuve_de_la_forme():
    fausse = 'function jesc(s){ gsub(/\\\\/,"\\\\\\\\",s); return s }\n'
    juste = 'function jesc(s){ gsub(/\\\\/,"&&",s); gsub(/"/,"\\\\\\"",s); gsub(/[\\\\"]/,"",m); return s }\n'
    if not idiomes_non_portables(fausse):
        return "l'idiome fautif n'est pas vu"
    if idiomes_non_portables(juste):
        return "`\"&&\"`, l'échappement du guillemet ou une suppression sont pris pour l'idiome fautif"
    dec = "function jstr(s, k){ return s }\n"
    lib = f"{VARIABLE}='{juste}'\n{VARIABLE_DECODAGE}='{dec}'\n"
    appel = f'awk "${VARIABLE}"\'{{ print jesc($0) }}\'\n'
    lecteur = f'awk "${VARIABLE}""${VARIABLE_DECODAGE}"\'{{ print jesc(jstr($0, "k")) }}\'\n'
    conforme = dict({"lib.sh": lib, "a.sh": appel}, **{n: lecteur for n in LECTEURS_JSON_EXIGES})
    if lire_la_forme(conforme)[0]:
        return f"une forme CONFORME est accusée : {lire_la_forme(conforme)[0]}"
    un_lecteur = sorted(LECTEURS_JSON_EXIGES)[0]
    ecarts = {
        "une seconde définition": dict(conforme, **{"a.sh": appel + juste}),
        "un appel sans inclusion": dict(conforme, **{"a.sh": "awk '{ print jesc($0) }'\n"}),
        "l'idiome fautif dans la lib": dict(conforme, **{"lib.sh": f"{VARIABLE}='{fausse}'\n{VARIABLE_DECODAGE}='{dec}'\n"}),
        "une lib sans la variable": dict(conforme, **{"lib.sh": juste + dec}),
        "un lecteur de JSON sans jstr": dict(conforme, **{un_lecteur: appel}),
        "jstr sans inclusion": dict(conforme, **{un_lecteur: f'awk "${VARIABLE}"\'{{ print jesc(jstr($0, "k")) }}\'\n'}),
        "une seconde définition de jstr": dict(conforme, **{"a.sh": appel + dec}),
    }
    for nom, fichiers in ecarts.items():
        if not lire_la_forme(fichiers)[0]:
            return f"« {nom} » n'est pas accusé"
    if lire_la_forme(conforme)[1] != {"a.sh"} | LECTEURS_JSON_EXIGES:
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
    for i, (_, e, v) in enumerate(valeurs_encodees()):
        lignes.append(
            '{"ClientHost":"192.0.2.%d","DownstreamContentSize":12,"DownstreamStatus":200,"Duration":1500000,'
            '"RequestHost":"h%d.example.test","RequestMethod":"GET%s","RequestPath":"/q?x=%s","RequestProtocol":"HTTP/1.1%s",'
            '"RouterName":"site@kubernetescrd","StartUTC":"2026-09-23T19:40:%02d.123456789Z","level":"info",'
            '"request_User-Agent":"%s","time":"2026-09-23T21:40:%02d+02:00"}' % (10 + i % 200, i, e, e, e, i % 60, e, i % 60))
        # P10.23-x : la méthode et le protocole sont DÉCODÉS comme le reste, donc échappés à l'écriture : un
        # `\"` décodé y fermait la chaîne (champ injecté), un `\\` y rendait l'enveloppe entière illisible.
        attendus.append({"ua": v, "path": "/q?x=" + v, "method": "GET" + v, "proto": "HTTP/1.1" + v})
    _ecrire(os.path.join(bac, "access.log"), "\n".join(lignes) + "\n")
    env.update(PLUME_WEB_SRC="file", PLUME_WEB_LOG=os.path.join(bac, "access.log"), PLUME_WEB_MAX="1000")
    return attendus


def banc_minio(bac, env):
    lignes, attendus = [], []
    for _, e, v in valeurs_encodees():
        lignes.append('{"status":"success","accessKey":"%s","policyName":"readonly","userStatus":"enabled"}' % e)
        attendus.append({"subject": v})
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


# auditd écrit un champ entre guillemets tant qu'il ne porte ni guillemet, ni octet hors de `!`..`~`
# (espace, contrôle, non-ASCII) ; sinon en hexadécimal majuscule, SANS guillemets (`audit_log_untrustedstring`
# du noyau). L'antislash passe donc BRUT entre guillemets ; une valeur à guillemet passe en hexadécimal, et le
# capteur doit rendre le texte DÉCODÉ (`P10.23-z`).
CORPUS_HEX_DATAACCESS = os.path.join(CAPTEURS, "dataaccess-hex.corpus")


def comme_auditd(v):
    if any(c == '"' or not "!" <= c <= "~" for c in v):
        return v.encode("utf-8").hex().upper()
    return f'"{v}"'


def cas_du_corpus_hex():
    """(cas, jeton name, jeton comm, path attendu, comm attendu) de `dataaccess-hex.corpus`."""
    cas = []
    with open(CORPUS_HEX_DATAACCESS, encoding="utf-8") as fh:
        for n, ligne in enumerate(fh, 1):
            ligne = ligne.rstrip("\n")
            if not ligne or ligne.startswith("#"):
                continue
            champs = ligne.split("\t")
            if len(champs) != 5:
                refus(f"collectors/dataaccess-hex.corpus:{n} : {len(champs)} colonne(s) au lieu de cinq")
            cas.append((champs[0], champs[1], champs[2], json.loads(champs[3]), json.loads(champs[4])))
    return cas


def nom_du_compte(auid):
    """Ce que `uname()` du capteur rend : `getent passwd`, sinon le numéro."""
    if shutil.which("getent") is None:
        return auid
    r = subprocess.run(["getent", "passwd", auid], capture_output=True, text=True, timeout=10)
    return r.stdout.split("\n", 1)[0].split(":", 1)[0] or auid


def banc_dataaccess(bac, env):
    lignes, attendus = [], []
    compte = nom_du_compte("1000")
    entrees = [(comme_auditd("/srv/donnees/" + v), comme_auditd(v[:15]), "/srv/donnees/" + v, v[:15])
               for _, v in VALEURS]
    entrees += [(nom, comm, chemin, comm_voulu) for _, nom, comm, chemin, comm_voulu in cas_du_corpus_hex()]
    for i, (nom, comm, chemin, comm_voulu) in enumerate(entrees):
        eid = "audit(1758650000.%03d:%d)" % (100 + i, 4000 + i)
        lignes.append(f"type=SYSCALL msg={eid}: arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc0000 "
                      f"a2=0 a3=0 items=1 ppid=1 pid={200 + i} auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
                      f'fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm={comm} exe="/usr/bin/cat" '
                      f'subj=unconfined key="plume_data"')
        lignes.append(f"type=PATH msg={eid}: item=0 name={nom} inode={10 + i} dev=fd:00 mode=0100644 "
                      f"ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0")
        # Le message est jugé aussi : il porte le nom DÉCODÉ, échappé une seule fois (P10.23-z).
        attendus.append({"path": chemin, "comm": comm_voulu,
                         "message": f"dataaccess: {compte} read {chemin} (key=plume_data, via {comm_voulu})"})
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
    # P10.32-f — le journal ClamAV de l'hôte n'est pas ce banc : sa lecture est coupée.
    env.update(PLUME_MAIL_SRC="file", PLUME_MAIL_LOG=os.path.join(bac, "mail.log"), PLUME_MAIL_MAX="1000",
               PLUME_MAIL_CLAMAV_LOG="", PLUME_MAIL_FRESHCLAM_LOG="")
    return attendus


def _champ(nom):
    return lambda ev: (ev.get("fields") or {}).get(nom)


# capteur -> (banc, sélection des événements jugés, champs jugés)
BANCS = {
    "web.sh": (banc_web, lambda ev: True, {"ua": _champ("ua"), "path": _champ("path"), "method": _champ("method"),
                                           "proto": _champ("proto")}),
    "minio.sh": (banc_minio, lambda ev: _champ("kind")(ev) == "user", {"subject": _champ("subject")}),
    "dataacl.sh": (banc_dataacl, lambda ev: "/arbre/" in (_champ("path")(ev) or ""), {"path": _champ("path")}),
    "dataaccess.sh": (banc_dataaccess, lambda ev: True, {"path": _champ("path"), "comm": _champ("comm"),
                                                           "message": lambda ev: ev.get("message")}),
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


def decodeur_livre():
    """Le texte de `_PLUME_AWK_DECODAGE_JSON`, lu en SOURÇANT `lib.sh`."""
    r = subprocess.run(["sh", "-c", '. "$1" && printf "%s" "${' + VARIABLE_DECODAGE + ':-}"', "sh", LIB],
                       capture_output=True, text=True, timeout=60)
    return r.stdout if r.returncode == 0 else ""


def epreuve_du_decodeur(chemin_awk, fonction, decodeur, quoi):
    """P10.23-x — `jesc(jstr(…))` sur chaque valeur, sous ses deux encodages : la valeur exacte ressort."""
    table = [(nom, '{"a":1,"k":"%s","z":"fin"}' % e, v) for nom, e, v in valeurs_encodees()]
    table += [(f"{nom} ({'ascii' if a else 'brut'})", '{"a":1,"k":"%s","z":"fin"}' % encode_comme_go(v, a), v)
              for nom, v in VALEURS_DE_CONTROLE for a in (False, True)]
    table += CAS_DU_DECODEUR
    with tempfile.TemporaryDirectory(prefix="garde-jstr-") as bac:
        cas = os.path.join(bac, "cas")
        _ecrire(cas, "".join(ligne + "\n" for _, ligne, _ in table))
        r = subprocess.run([chemin_awk, fonction + decodeur + '\n{ print "{\\"v\\":\\"" jesc(jstr($0, "k")) "\\"}" }', cas],
                           capture_output=True, timeout=60)
    if r.returncode != 0:
        return [f"{quoi} : le décodeur livré ne tourne pas : {r.stderr.decode('utf-8', 'replace').strip()[:300]}"]
    fautes = []
    for (nom, e, v), ligne in zip(table, r.stdout.decode("utf-8", "surrogateescape").split("\n")):
        voulu = CONTROLE.sub(" ", v)
        try:
            obtenu = json.loads(ligne)["v"]
        except (ValueError, KeyError) as x:
            fautes.append(f"{quoi} : {nom} {e!r} -> {ligne!r}, illisible comme JSON ({x})")
            continue
        if obtenu != voulu:
            fautes.append(f"{quoi} : {nom} {e!r} -> décodé {obtenu!r} au lieu de {voulu!r}")
    return fautes


def epreuve_du_cout(chemin_awk, fonction, decodeur, quoi):
    """P10.23-x — une valeur de ECHAPPEMENTS_DU_COUT échappements (`\\u003c` et `\\"` alternés) décodée sous budget."""
    n = ECHAPPEMENTS_DU_COUT // 2
    with tempfile.TemporaryDirectory(prefix="garde-jstr-cout-") as bac:
        cas = os.path.join(bac, "cas")
        _ecrire(cas, '{"a":1,"k":"%s","z":"fin"}\n' % ('\\u003c\\"' * n))
        try:
            r = subprocess.run([chemin_awk, fonction + decodeur + '\n{ x = jstr($0, "k"); print length(x) }', cas],
                               capture_output=True, timeout=BUDGET_DU_COUT_S)
        except subprocess.TimeoutExpired:
            return [f"{quoi} : {ECHAPPEMENTS_DU_COUT} échappements non décodés en {BUDGET_DU_COUT_S} s — un coût "
                    "qui croît plus vite que la valeur, à la main de tout client (chemin, User-Agent)"]
    if r.returncode != 0 or r.stdout.decode().strip() != str(2 * n):
        return [f"{quoi} : {ECHAPPEMENTS_DU_COUT} échappements décodés en {r.stdout.decode().strip()!r} caractère(s) "
                f"au lieu de {2 * n} (rc={r.returncode})"]
    return []


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
    if not os.path.exists(CORPUS_HEX_DATAACCESS):
        refus("`collectors/dataaccess-hex.corpus` introuvable (banc de `dataaccess.sh`, `P10.23-z`)")
    manques = [nom for nom, vrai in PIEGES_EXIGES.items() if not any(vrai(v) for _, v in VALEURS)]
    if manques:
        refus("table des valeurs sous son plancher : " + " ; ".join(manques))
    fautes, appelants = lire_la_forme(fichiers)
    # P10.23-z : le décodage du nom (boucle octet par octet de jhex()) vient APRÈS le filtre auid et le
    # plafond de 600 ; sinon chaque PATH écarté le paie (3000 noms hex de 3,9 Ko : 4,5 s -> 14,5 s sous mawk).
    da = fichiers.get("dataaccess.sh", "")
    p_auid, p_plafond = da.find('if(au==""||'), da.find("if(n>=600)next")
    p_decode = da.find('jval(fraw($0,"name"))')
    if min(p_auid, p_plafond, p_decode) < 0 or not p_auid < p_plafond < p_decode:
        fautes.append("collectors/dataaccess.sh décode le nom (`jval(fraw($0,\"name\"))`) avant le filtre auid "
                      "ou le plafond de 600 : chaque PATH écarté paie la boucle de jhex()")
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
    decodeur = decodeur_livre()
    if not decodeur:
        fautes.append(f"`{VARIABLE_DECODAGE}` introuvable en sourçant `lib.sh` : le décodeur livré n'est pas joué")
    for version, chemin in awks:
        if fonction:
            fautes += epreuve_de_la_fonction(chemin, fonction, f"fonction ({version})")
        if fonction and decodeur:
            f = epreuve_du_decodeur(chemin, fonction, decodeur, f"décodeur ({version})")
            f += epreuve_du_cout(chemin, fonction, decodeur, f"coût du décodeur ({version})")
            print(f"{ETIQUETTE} : décodeur jstr  {version:<22} " + ("tenu" if not f else f"{len(f)} défaut(s) — {f[0][:160]}"))
            fautes += f
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
          f"les {len(VALEURS)} valeurs à antislash exactes ; `web.sh` et `minio.sh` rendent DÉCODÉES les "
          f"{len(valeurs_encodees())} valeurs encodées comme Go (P10.23-x), sous : {exerces}.")
    sys.exit(0)


if __name__ == "__main__":
    main()
